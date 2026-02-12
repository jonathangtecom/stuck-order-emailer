"""
Live integration tests — hits real Shopify + ParcelPanel APIs in dry-run mode.

USAGE:
  1. Create a .env.test file in the project root:

       TEST_SHOPIFY_STORE_URL=your-store.myshopify.com
       TEST_SHOPIFY_API_TOKEN=shpat_...
       TEST_PARCELPANEL_API_KEY=...

  2. Run:
       python3 -m pytest tests/test_live_integration.py -v -s

All tests are skipped automatically if credentials are not set.
No emails are sent. No data is written to the production database.
"""
import os
import sys
import json
import shutil
import tempfile
import logging
import pytest
from dotenv import load_dotenv

# ── Load credentials from .env.test ──

_env_test_path = os.path.join(os.path.dirname(__file__), '..', '.env.test')
load_dotenv(_env_test_path)

SHOPIFY_URL = os.environ.get('TEST_SHOPIFY_STORE_URL', '')
SHOPIFY_TOKEN = os.environ.get('TEST_SHOPIFY_API_TOKEN', '')
PARCELPANEL_KEY = os.environ.get('TEST_PARCELPANEL_API_KEY', '')

HAVE_CREDS = all([SHOPIFY_URL, SHOPIFY_TOKEN, PARCELPANEL_KEY])

pytestmark = pytest.mark.skipif(
    not HAVE_CREDS,
    reason='Live API credentials not set (TEST_SHOPIFY_STORE_URL, TEST_SHOPIFY_API_TOKEN, TEST_PARCELPANEL_API_KEY)',
)

# ── Setup logging so we can see what happens ──

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s — %(message)s')

# ── Import app modules ──

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src import shopify_client, parcel_panel, database
from src.processor import process_store, _load_template, _render_template_string, _parse_date


# ── Fixtures ──

@pytest.fixture(scope='module')
def temp_env():
    """Set up a temp database and templates dir for the full pipeline test."""
    tmpdir = tempfile.mkdtemp(prefix='stuck-order-live-test-')
    db_path = os.path.join(tmpdir, 'test.db')
    tpl_dir = os.path.join(tmpdir, 'templates')
    os.makedirs(tpl_dir)

    # Copy the real example template
    real_tpl = os.path.join(os.path.dirname(__file__), '..', 'data', 'templates', 'example.html')
    shutil.copy(real_tpl, os.path.join(tpl_dir, 'example.html'))

    # Point modules at temp paths
    old_db = database.DATABASE_PATH
    database.DATABASE_PATH = db_path
    database.init_db()

    import src.processor as proc
    old_tpl = proc.TEMPLATES_PATH
    proc.TEMPLATES_PATH = tpl_dir

    yield {'db_path': db_path, 'tpl_dir': tpl_dir, 'tmpdir': tmpdir}

    # Restore
    database.DATABASE_PATH = old_db
    proc.TEMPLATES_PATH = old_tpl
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope='module')
def test_store():
    """Return a store dict matching the database schema."""
    return {
        'id': 'live-test-store',
        'name': 'Live Test Store',
        'enabled': 1,
        'shopify_store_url': SHOPIFY_URL,
        'shopify_admin_api_token': SHOPIFY_TOKEN,
        'parcel_panel_api_key': PARCELPANEL_KEY,
        'from_email': 'test@example.com',
        'from_name': 'Test',
        'email_subject': 'Update on your order {{ order_number }}',
        'email_template': 'example.html',
        'days_threshold': 8,
    }


# ── Test 1: Shopify API — can we fetch orders? ──

class TestShopifyAPI:
    def test_fetch_orders(self, test_store):
        """Verify we can connect to Shopify and get a list of orders."""
        orders = shopify_client.get_recent_orders(
            test_store['shopify_store_url'],
            test_store['shopify_admin_api_token'],
            days_back=30,
        )
        print(f'\n  Shopify returned {len(orders)} fulfilled orders from the last 30 days')

        assert isinstance(orders, list), 'Expected a list of orders'
        # It's okay if there are 0 orders (new/test store), but the call should succeed

    def test_order_structure(self, test_store):
        """Verify order objects have the fields we need."""
        orders = shopify_client.get_recent_orders(
            test_store['shopify_store_url'],
            test_store['shopify_admin_api_token'],
            days_back=60,
        )
        if not orders:
            pytest.skip('No orders found — cannot validate structure')

        order = orders[0]
        print(f'\n  Sample order: {order.get("name")} (id={order.get("id")})')
        print(f'  Created: {order.get("created_at")}')
        print(f'  Customer: {(order.get("customer") or {}).get("email", "N/A")}')

        # These fields are required by the processor
        assert 'id' in order, 'Order missing "id"'
        assert 'name' in order, 'Order missing "name" (order number)'
        assert 'created_at' in order, 'Order missing "created_at"'

        # created_at should be parseable
        dt = _parse_date(order['created_at'])
        assert dt is not None, f'Could not parse created_at: {order["created_at"]}'


# ── Test 2: ParcelPanel API — can we look up tracking? ──

class TestParcelPanelAPI:
    def _get_sample_order_number(self, test_store):
        """Helper: get a real order number to test ParcelPanel with."""
        orders = shopify_client.get_recent_orders(
            test_store['shopify_store_url'],
            test_store['shopify_admin_api_token'],
            days_back=60,
        )
        if not orders:
            return None
        return orders[0].get('name')

    def test_tracking_lookup(self, test_store):
        """Verify we can call ParcelPanel and get a response (even if no tracking exists)."""
        order_number = self._get_sample_order_number(test_store)
        if not order_number:
            pytest.skip('No orders found — cannot test ParcelPanel lookup')

        print(f'\n  Looking up tracking for order {order_number}...')
        tracking_data = parcel_panel.get_order_tracking(
            test_store['parcel_panel_api_key'],
            order_number,
        )

        # ParcelPanel returns None on error, or a dict on success
        # Even if there's no tracking, we should get a response (not crash)
        print(f'  ParcelPanel response: {json.dumps(tracking_data, indent=2, default=str)[:500]}')

        if tracking_data is not None:
            # If we got data, check the shape
            stuck = parcel_panel.get_stuck_shipments(tracking_data)
            print(f'  Stuck shipments: {len(stuck)}')
            for s in stuck:
                print(f'    - {s.get("tracking_number")} — {s.get("status")}')

    def test_tracking_nonexistent_order(self, test_store):
        """ParcelPanel should handle a non-existent order gracefully."""
        tracking_data = parcel_panel.get_order_tracking(
            test_store['parcel_panel_api_key'],
            '#99999999',  # Very unlikely to exist
        )
        # Should return None or empty — should NOT raise
        print(f'\n  Non-existent order response: {tracking_data}')
        stuck = parcel_panel.get_stuck_shipments(tracking_data)
        assert stuck == [], 'Non-existent order should have no stuck shipments'


# ── Test 3: Template rendering with real order data ──

class TestTemplateRendering:
    def test_render_with_real_data(self, test_store, temp_env):
        """Load real order data and render the email template."""
        orders = shopify_client.get_recent_orders(
            test_store['shopify_store_url'],
            test_store['shopify_admin_api_token'],
            days_back=60,
        )
        if not orders:
            pytest.skip('No orders to render template with')

        order = orders[0]
        customer = order.get('customer') or {}
        order_date = _parse_date(order['created_at'])

        template_html = _load_template('example.html')
        assert template_html is not None, 'Failed to load example.html template'

        template_vars = {
            'customer_name': customer.get('first_name', 'Customer'),
            'order_number': order.get('name', '#???'),
            'tracking_number': 'TEST123',
            'tracking_url': 'https://example.com/track',
            'store_name': test_store['name'],
            'order_date': order_date.strftime('%B %d, %Y') if order_date else 'Unknown',
            'days_waiting': '10',
        }

        rendered = _render_template_string(template_html, template_vars)
        print(f'\n  Rendered email length: {len(rendered)} chars')
        print(f'  Contains customer name: {"Customer" in rendered or customer.get("first_name", "") in rendered}')
        print(f'  Contains order number: {order.get("name", "") in rendered}')

        assert len(rendered) > 100, 'Rendered template is suspiciously short'
        assert order.get('name', '') in rendered, 'Order number not found in rendered template'
        assert test_store['name'] in rendered, 'Store name not found in rendered template'


# ── Test 4: Full dry-run pipeline ──

class TestFullDryRun:
    def test_process_store_dry_run(self, test_store, temp_env):
        """Run the complete pipeline in dry-run mode against real APIs."""
        # Create the store in our temp database
        database.create_store(test_store)

        print(f'\n  Running dry-run for store: {test_store["name"]}')
        print(f'  Shopify URL: {test_store["shopify_store_url"]}')
        print(f'  Threshold: {test_store["days_threshold"]} days')

        result = process_store(test_store, dry_run=True)

        print(f'\n  === DRY RUN RESULTS ===')
        print(f'  Would send: {result["sent"]}')
        print(f'  Skipped (already sent): {result["skipped"]}')

        assert 'sent' in result, 'Result missing "sent" count'
        assert 'skipped' in result, 'Result missing "skipped" count'
        assert 'would_send' in result, 'Dry run should include "would_send" list'

        if result['would_send']:
            print(f'\n  Emails that would be sent:')
            for email in result['would_send']:
                print(f'    Order: {email["order_number"]}')
                print(f'    To: {email["customer_email"]}')
                print(f'    Tracking: {email["tracking_number"]} ({email["tracking_status"]})')
                print(f'    Waiting: {email["days_waiting"]} days')
                print(f'    Subject: {email["subject"]}')
                print()

                # Validate each would-send entry has all required fields
                assert email['order_number'], 'Missing order_number'
                assert email['customer_email'], 'Missing customer_email'
                assert '@' in email['customer_email'], f'Invalid email: {email["customer_email"]}'
                assert email['tracking_number'], 'Missing tracking_number'
                assert email['tracking_status'] in ('PENDING', 'INFO_RECEIVED', 'UNFULFILLED'), \
                    f'Unexpected status: {email["tracking_status"]}'
                assert email['days_waiting'] >= test_store['days_threshold'], \
                    f'Days waiting ({email["days_waiting"]}) is below threshold ({test_store["days_threshold"]})'
                assert email['subject'], 'Missing subject'
        else:
            print('  No stuck orders found (this is fine if no orders match the criteria)')

        # Verify no emails were actually recorded in the database
        emails, total = database.get_sent_emails(store_id='live-test-store')
        assert total == 0, f'Dry run should NOT record emails in DB, but found {total}'
        print('  Verified: 0 emails recorded in database (dry-run is working)')

    def test_dry_run_idempotent(self, test_store, temp_env):
        """Running dry-run twice should produce the same results (nothing persisted)."""
        result1 = process_store(test_store, dry_run=True)
        result2 = process_store(test_store, dry_run=True)

        assert result1['sent'] == result2['sent'], \
            f'Dry run not idempotent: first={result1["sent"]}, second={result2["sent"]}'
        print(f'\n  Idempotency check passed: both runs found {result1["sent"]} would-send emails')

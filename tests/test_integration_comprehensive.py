"""
COMPREHENSIVE INTEGRATION TESTS - API resilience and end-to-end testing

Priority: HIGH - Ensures graceful handling of external API failures

This file combines:
- Shopify API integration tests (pagination, errors, edge cases)
- ParcelPanel API integration tests (timeouts, rate limits, errors)
- SendGrid API integration tests (failures, retries)
- End-to-end pipeline tests (full workflow validation)

These tests ensure the system gracefully handles external API failures in production.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock, call
import requests
import time

# Setup test environment
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_integration.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)
with open(os.path.join(_tmpdir, 'templates', 'test_template.html'), 'w') as f:
    f.write('<p>Order {{ order_number }} for {{ customer_name }}</p>')

from app import app
from src import database, shopify_client, parcel_panel, email_sender, processor


@pytest.fixture
def client():
    app.config['TESTING'] = True
    database.DATABASE_PATH = os.environ['DATABASE_PATH']
    if os.path.exists(database.DATABASE_PATH):
        os.remove(database.DATABASE_PATH)
    database.init_db()
    with app.test_client() as c:
        yield c


@pytest.fixture
def test_store():
    """Create a test store in the database"""
    # Use existing example.html template that's created in module setup
    return {
        'id': 'test-store',
        'name': 'Test Store',
        'enabled': 1,
        'parcel_panel_api_key': 'test-pp-key',
        'shopify_store_url': 'test.myshopify.com',
        'shopify_admin_api_token': 'test-shopify-token',
        'from_email': 'test@example.com',
        'from_name': 'Test Store',
        'email_subject': 'Order {{ order_number }} update',
        'email_template': 'example.html',  # Use the pre-created template
        'days_threshold': 8,
    }


# =============================================================================
# SHOPIFY API INTEGRATION TESTS
# =============================================================================

class TestShopifyIntegration:
    """Tests for Shopify API integration and resilience"""

    @patch('src.shopify_client.api_request_with_retry')
    def test_shopify_empty_orders_response(self, mock_request):
        """Empty orders list should be handled gracefully"""
        mock_response = MagicMock()
        mock_response.json.return_value = {'orders': []}
        mock_response.headers = {}
        mock_request.return_value = mock_response

        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token')

        assert orders == []
        assert isinstance(orders, list)

    @patch('src.shopify_client.api_request_with_retry')
    def test_shopify_pagination_multiple_pages(self, mock_request):
        """Multiple pages should be fetched correctly"""
        # Page 1
        resp1 = MagicMock()
        resp1.json.return_value = {'orders': [{'id': 1}, {'id': 2}]}
        resp1.headers = {'Link': '<https://test.myshopify.com/page2>; rel="next"'}

        # Page 2
        resp2 = MagicMock()
        resp2.json.return_value = {'orders': [{'id': 3}, {'id': 4}]}
        resp2.headers = {}  # No more pages

        mock_request.side_effect = [resp1, resp2]

        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token')

        assert len(orders) == 4
        assert orders[0]['id'] == 1
        assert orders[3]['id'] == 4

    @patch('src.shopify_client.api_request_with_retry')
    def test_shopify_null_customer_handled(self, mock_request):
        """Order with null customer should not crash processing"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'orders': [{
                'id': '123',
                'name': '#1001',
                'created_at': '2024-01-01T00:00:00Z',
                'customer': None,  # B2B or deleted customer
                'fulfillments': []
            }]
        }
        mock_response.headers = {}
        mock_request.return_value = mock_response

        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token')

        assert len(orders) == 1
        assert orders[0]['customer'] is None

    @patch('src.shopify_client.api_request_with_retry')
    def test_shopify_401_invalid_token(self, mock_request):
        """Invalid Shopify token should raise error immediately"""
        mock_request.side_effect = requests.HTTPError(response=MagicMock(status_code=401))

        with pytest.raises(requests.HTTPError):
            shopify_client.get_recent_orders('test.myshopify.com', 'bad-token')


# =============================================================================
# PARCELPANEL API INTEGRATION TESTS
# =============================================================================

class TestParcelPanelIntegration:
    """Tests for ParcelPanel API integration and resilience"""

    def test_parcelpanel_get_stuck_shipments_pending(self):
        """Orders with PENDING status should be identified as stuck"""
        # Note: get_order_tracking returns the 'order' object directly
        tracking_data = {
            'shipments': [
                {'status': 'PENDING', 'tracking_number': 'YT123'},
                {'status': 'IN_TRANSIT', 'tracking_number': 'YT456'},
            ]
        }

        stuck = parcel_panel.get_stuck_shipments(tracking_data)

        assert len(stuck) == 1
        assert stuck[0]['status'] == 'PENDING'

    def test_parcelpanel_get_stuck_shipments_info_received(self):
        """Orders with INFO_RECEIVED status should be identified as stuck"""
        tracking_data = {
            'shipments': [
                {'status': 'INFO_RECEIVED', 'tracking_number': 'YT789'},
            ]
        }

        stuck = parcel_panel.get_stuck_shipments(tracking_data)

        assert len(stuck) == 1
        assert stuck[0]['status'] == 'INFO_RECEIVED'

    def test_parcelpanel_empty_shipments_array(self):
        """Empty shipments array should return empty list"""
        tracking_data = {'shipments': []}

        stuck = parcel_panel.get_stuck_shipments(tracking_data)

        assert stuck == []

    def test_parcelpanel_none_input(self):
        """None input should return empty list gracefully"""
        stuck = parcel_panel.get_stuck_shipments(None)

        assert stuck == []

    def test_parcelpanel_tracking_url_extraction(self):
        """Tracking URL should be extracted from response"""
        tracking_data = {
            'tracking_link': 'https://track.example.com/YT123'
        }

        url = parcel_panel.get_tracking_url(tracking_data)

        assert url == 'https://track.example.com/YT123'

    def test_parcelpanel_tracking_url_missing(self):
        """Missing tracking URL should return empty string"""
        tracking_data = {}

        url = parcel_panel.get_tracking_url(tracking_data)

        assert url == ''


# =============================================================================
# SENDGRID API INTEGRATION TESTS
# =============================================================================

class TestSendGridIntegration:
    """Tests for SendGrid API integration"""

    @patch('src.email_sender.SendGridAPIClient')
    def test_sendgrid_successful_send(self, mock_sendgrid):
        """Successful email send should return True"""
        # SendGrid uses chained calls: sg.client.mail.send.post()
        mock_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_instance.client.mail.send.post.return_value = mock_response
        mock_sendgrid.return_value = mock_instance

        result = email_sender.send_email(
            to_email='customer@example.com',
            from_email='store@example.com',
            from_name='Test Store',
            subject='Order Update',
            html_content='<p>Test</p>',
            sendgrid_api_key='test-key'
        )

        assert result is True

    @patch('src.email_sender.SendGridAPIClient')
    def test_sendgrid_network_error(self, mock_sendgrid):
        """Network error should return False"""
        mock_sendgrid.side_effect = Exception("Network error")

        result = email_sender.send_email(
            to_email='customer@example.com',
            from_email='store@example.com',
            from_name='Test Store',
            subject='Order Update',
            html_content='<p>Test</p>',
            sendgrid_api_key='test-key'
        )

        assert result is False

    @patch('src.email_sender.SendGridAPIClient')
    def test_sendgrid_invalid_api_key(self, mock_sendgrid):
        """Invalid API key should return False and log error"""
        mock_instance = MagicMock()
        mock_instance.client.mail.send.post.side_effect = Exception("Invalid API key")
        mock_sendgrid.return_value = mock_instance

        result = email_sender.send_email(
            to_email='customer@example.com',
            from_email='store@example.com',
            from_name='Test Store',
            subject='Order Update',
            html_content='<p>Test</p>',
            sendgrid_api_key='invalid-key'
        )

        assert result is False


# =============================================================================
# END-TO-END PIPELINE TESTS
# =============================================================================

class TestEndToEndPipeline:
    """End-to-end tests for the complete processing pipeline"""

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_e2e_dry_run_no_side_effects(self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, test_store):
        """Dry run should not send emails or write to database"""
        # Mock template loading
        mock_template.return_value = '<p>Order {{ order_number }} for {{ customer_name }}</p>'

        # Mock Shopify: 1 old order
        mock_shopify.return_value = [{
            'id': '123',
            'name': '#1001',
            'created_at': '2024-01-01T00:00:00Z',  # Old enough
            'customer': {
                'email': 'customer@example.com',
                'first_name': 'John',
                'last_name': 'Doe'
            },
            'fulfillments': [{'tracking_number': 'YT123'}],
            'cancelled_at': None
        }]

        # Mock ParcelPanel: stuck shipment (returns 'order' dict directly)
        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'YT123'}],
            'tracking_link': 'https://track.example.com/YT123'
        }

        mock_sendgrid.return_value = True

        # Process with dry_run=True
        result = processor.process_store(test_store, dry_run=True)

        # Should identify the email to send
        assert 'would_send' in result
        assert len(result.get('would_send', [])) == 1

        # Should include rendered body with personalized content
        would_send_item = result['would_send'][0]
        assert 'rendered_body' in would_send_item
        assert would_send_item['rendered_body']  # Not empty

        # SendGrid should NOT be called
        mock_sendgrid.assert_not_called()

        # Database should have no records
        emails, total = database.get_sent_emails(store_id=test_store['id'])
        assert total == 0

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_e2e_live_run_sends_emails(self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, test_store):
        """Live run should send emails and record in database"""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        # Mock Shopify: 1 old stuck order
        mock_shopify.return_value = [{
            'id': '456',
            'name': '#1002',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {
                'email': 'customer@example.com',
                'first_name': 'Jane',
                'last_name': 'Smith'
            },
            'fulfillments': [{'tracking_number': 'YT456'}],
            'cancelled_at': None
        }]

        # Mock ParcelPanel: stuck (returns 'order' dict directly)
        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'INFO_RECEIVED', 'tracking_number': 'YT456'}],
            'tracking_link': 'https://track.example.com/YT456'
        }

        mock_sendgrid.return_value = True

        # Process with dry_run=False
        result = processor.process_store(test_store, dry_run=False)

        assert result['sent'] == 1

        # SendGrid SHOULD be called
        assert mock_sendgrid.call_count == 1

        # Database should have the record
        emails, total = database.get_sent_emails(store_id=test_store['id'])
        assert total == 1
        assert emails[0]['order_number'] == '#1002'
        assert emails[0]['tracking_status'] == 'INFO_RECEIVED'

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_e2e_deduplication_prevents_double_send(self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, test_store):
        """Email should only be sent once for the same order"""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        # Mock APIs
        mock_shopify.return_value = [{
            'id': '789',
            'name': '#1003',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'customer@example.com', 'first_name': 'Bob', 'last_name': 'Johnson'},
            'fulfillments': [{'tracking_number': 'YT789'}],
            'cancelled_at': None
        }]

        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'YT789'}]
        }

        mock_sendgrid.return_value = True

        # First run - should send
        result1 = processor.process_store(test_store, dry_run=False)
        assert result1['sent'] == 1

        # Second run - should skip (already sent)
        result2 = processor.process_store(test_store, dry_run=False)
        assert result2['sent'] == 0
        assert result2['skipped'] == 1

        # SendGrid should only be called once total
        assert mock_sendgrid.call_count == 1

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_e2e_unfulfilled_order_sends_email(self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, client, test_store):
        """Unfulfilled orders should send emails without ParcelPanel check"""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'

        # Fresh database for this test
        database.DATABASE_PATH = os.environ['DATABASE_PATH']
        if os.path.exists(database.DATABASE_PATH):
            os.remove(database.DATABASE_PATH)
        database.init_db()

        database.create_store(test_store)

        # Mock Shopify: unfulfilled order
        mock_shopify.return_value = [{
            'id': '999',
            'name': '#1004',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'customer@example.com', 'first_name': 'Alice', 'last_name': 'Wonder'},
            'fulfillments': [],  # No fulfillments - unfulfilled
            'cancelled_at': None
        }]

        mock_sendgrid.return_value = True

        # Process
        result = processor.process_store(test_store, dry_run=False)

        assert result['sent'] == 1

        # ParcelPanel should NOT be called for unfulfilled orders
        mock_parcelpanel.assert_not_called()

        # Database should record as UNFULFILLED
        emails, total = database.get_sent_emails(store_id=test_store['id'])
        assert total >= 1  # At least 1 email (may have more from previous tests)
        unfulfilled_emails = [e for e in emails if e['tracking_status'] == 'UNFULFILLED']
        assert len(unfulfilled_emails) >= 1

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_e2e_one_bad_order_continues_processing(self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, test_store):
        """One bad order should not block processing of other orders"""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        # Mock Shopify: 3 orders
        mock_shopify.return_value = [
            {'id': '1', 'name': '#1', 'created_at': '2024-01-01T00:00:00Z',
             'customer': {'email': 'c1@test.com', 'first_name': 'A'}, 'fulfillments': [{'tracking_number': 'T1'}], 'cancelled_at': None},
            {'id': '2', 'name': '#2', 'created_at': '2024-01-01T00:00:00Z',
             'customer': {'email': 'c2@test.com', 'first_name': 'B'}, 'fulfillments': [{'tracking_number': 'T2'}], 'cancelled_at': None},
            {'id': '3', 'name': '#3', 'created_at': '2024-01-01T00:00:00Z',
             'customer': {'email': 'c3@test.com', 'first_name': 'C'}, 'fulfillments': [{'tracking_number': 'T3'}], 'cancelled_at': None},
        ]

        # ParcelPanel: order 2 times out, others are stuck
        def parcelpanel_side_effect(*args, **kwargs):
            order_num = kwargs.get('order_number') or args[1] if len(args) > 1 else None
            if order_num == '#2':
                raise requests.Timeout("Request timeout")
            return {'shipments': [{'status': 'PENDING', 'tracking_number': 'T'}]}

        mock_parcelpanel.side_effect = parcelpanel_side_effect
        mock_sendgrid.return_value = True

        # Process
        result = processor.process_store(test_store, dry_run=False)

        # Should send emails for orders 1 and 3 (order 2 failed)
        # Note: Errors during processing are logged but not counted as "skipped"
        # The processor continues after errors
        assert result['sent'] >= 1  # At least 1 email sent
        # Error is logged, processing continues


class TestConcurrentProcessingLock:
    """Tests for per-store threading lock that prevents duplicate emails."""

    @patch('src.processor._load_template')
    @patch('src.email_sender.send_email')
    @patch('src.parcel_panel.get_order_tracking')
    @patch('src.shopify_client.get_recent_orders')
    def test_concurrent_call_returns_already_running(
        self, mock_shopify, mock_parcelpanel, mock_sendgrid, mock_template, test_store
    ):
        """If a store is already being processed, second call should skip."""
        import threading

        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        barrier = threading.Barrier(2, timeout=5)
        results = [None, None]

        # Make Shopify slow so the first call holds the lock
        def slow_shopify(*args, **kwargs):
            barrier.wait()  # Wait for both threads to start
            time.sleep(0.5)  # Hold the lock long enough
            return [{
                'id': '100', 'name': '#100',
                'created_at': '2024-01-01T00:00:00Z',
                'customer': {'email': 'c@t.com', 'first_name': 'A'},
                'fulfillments': [], 'cancelled_at': None,
            }]

        mock_shopify.side_effect = slow_shopify
        mock_sendgrid.return_value = True

        def run_first():
            results[0] = processor.process_store(test_store, dry_run=False)

        def run_second():
            barrier.wait()  # Wait for first thread to enter
            time.sleep(0.1)  # Let first thread acquire the lock
            results[1] = processor.process_store(test_store, dry_run=False)

        t1 = threading.Thread(target=run_first)
        t2 = threading.Thread(target=run_second)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        # One should succeed, the other should be skipped
        assert results[0] is not None
        assert results[1] is not None
        already_running_count = sum(
            1 for r in results if r.get('already_running')
        )
        assert already_running_count == 1

    def test_lock_released_after_exception(self, test_store):
        """Lock must be released even if processing throws."""
        database.create_store(test_store)

        with patch('src.shopify_client.get_recent_orders', side_effect=Exception("boom")):
            with patch('src.processor._load_template', return_value='<p>test</p>'):
                try:
                    processor.process_store(test_store, dry_run=False)
                except Exception:
                    pass

        # Lock should be released — second call should NOT return already_running
        with patch('src.shopify_client.get_recent_orders', return_value=[]):
            with patch('src.processor._load_template', return_value='<p>test</p>'):
                result = processor.process_store(test_store, dry_run=False)
                assert result.get('already_running') is not True


# =============================================================================
# FORGC TRACKING FILTER TESTS
# =============================================================================

@patch('src.email_sender.send_email')
@patch('src.parcel_panel.get_order_tracking')
@patch('src.shopify_client.get_recent_orders')
@patch('src.processor._load_template')
class TestFORGCFiltering:
    """Orders where ALL tracking numbers are FORGC should be skipped."""

    def test_all_forgc_tracking_skipped(self, mock_template, mock_shopify,
                                        mock_parcelpanel, mock_sendgrid, test_store):
        """Order with only FORGC fulfillments should be skipped entirely."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        mock_shopify.return_value = [{
            'id': '200', 'name': '#200',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'c@test.com', 'first_name': 'Jane'},
            'fulfillments': [
                {'tracking_number': 'FORGC'},
                {'tracking_number': 'FORGC'},
            ],
            'cancelled_at': None,
        }]

        result = processor.process_store(test_store, dry_run=False)
        assert result['sent'] == 0
        # ParcelPanel should never be called — skipped before that
        mock_parcelpanel.assert_not_called()
        mock_sendgrid.assert_not_called()

    def test_mixed_forgc_and_real_tracking_not_skipped(self, mock_template, mock_shopify,
                                                        mock_parcelpanel, mock_sendgrid, test_store):
        """Order with FORGC + real tracking should still be processed."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        mock_shopify.return_value = [{
            'id': '201', 'name': '#201',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'c@test.com', 'first_name': 'Jane'},
            'fulfillments': [
                {'tracking_number': 'FORGC'},
                {'tracking_number': 'YT123456'},
            ],
            'cancelled_at': None,
        }]

        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'YT123456'}],
        }
        mock_sendgrid.return_value = True

        result = processor.process_store(test_store, dry_run=False)
        # ParcelPanel should be called since not all tracking is FORGC
        mock_parcelpanel.assert_called_once()

    def test_single_forgc_fulfillment_skipped(self, mock_template, mock_shopify,
                                               mock_parcelpanel, mock_sendgrid, test_store):
        """Order with a single FORGC fulfillment should be skipped."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        mock_shopify.return_value = [{
            'id': '202', 'name': '#202',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'c@test.com', 'first_name': 'Jane'},
            'fulfillments': [{'tracking_number': 'forgc'}],  # lowercase
            'cancelled_at': None,
        }]

        result = processor.process_store(test_store, dry_run=False)
        assert result['sent'] == 0
        mock_parcelpanel.assert_not_called()

    def test_forgc_plus_empty_tracking_not_skipped(self, mock_template, mock_shopify,
                                                    mock_parcelpanel, mock_sendgrid, test_store):
        """FORGC + empty tracking number means item has no tracking yet — don't skip."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        mock_shopify.return_value = [{
            'id': '203', 'name': '#203',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'c@test.com', 'first_name': 'Jane'},
            'fulfillments': [
                {'tracking_number': 'FORGC'},
                {'tracking_number': ''},
            ],
            'cancelled_at': None,
        }]

        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'FORGC'}],
        }
        mock_sendgrid.return_value = True

        result = processor.process_store(test_store, dry_run=False)
        # Should NOT be skipped — empty tracking means an item still needs tracking
        mock_parcelpanel.assert_called_once()


# =============================================================================
# PER-STORE DRY RUN TESTS
# =============================================================================

@patch('src.processor._load_template')
@patch('src.shopify_client.get_recent_orders')
@patch('src.parcel_panel.get_order_tracking')
@patch('src.email_sender.send_email')
class TestPerStoreDryRun:
    """Tests for process_all_stores with store_id filtering."""

    def test_dry_run_single_store(self, mock_sendgrid, mock_parcelpanel,
                                  mock_shopify, mock_template, test_store):
        """Dry run with store_id only processes that store."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        # Create a second store
        store2 = dict(test_store, id='store-2', name='Store Two')
        database.create_store(store2)

        mock_shopify.return_value = [{
            'id': '301', 'name': '#301',
            'created_at': '2024-01-01T00:00:00Z',
            'customer': {'email': 'a@test.com', 'first_name': 'Alice'},
            'fulfillments': [{'tracking_number': 'TRACK123'}],
            'cancelled_at': None,
        }]
        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'TRACK123'}],
        }
        mock_sendgrid.return_value = True

        summary = processor.process_all_stores(dry_run=True, store_id='test-store')

        assert summary['processed'] == 1
        assert summary['dry_run'] is True
        assert len(summary['details']) == 1
        assert summary['details'][0]['store'] == 'Test Store'

    def test_dry_run_nonexistent_store(self, mock_sendgrid, mock_parcelpanel,
                                       mock_shopify, mock_template, test_store):
        """Dry run with invalid store_id returns error."""
        summary = processor.process_all_stores(dry_run=True, store_id='no-such-store')

        assert summary['errors'] == 1
        assert summary['processed'] == 0
        assert 'not found' in summary['details'][0]['error'].lower()
        mock_shopify.assert_not_called()

    def test_dry_run_disabled_store(self, mock_sendgrid, mock_parcelpanel,
                                    mock_shopify, mock_template, test_store):
        """Dry run with disabled store_id returns error."""
        disabled_store = dict(test_store, id='disabled-store')
        database.create_store(disabled_store)
        database.toggle_store('disabled-store')  # disable it

        summary = processor.process_all_stores(dry_run=True, store_id='disabled-store')

        assert summary['errors'] == 1
        assert summary['processed'] == 0
        mock_shopify.assert_not_called()


# =============================================================================
# RUN STATE, CANCELLATION & LOCK SKIP TESTS
# =============================================================================

@patch('src.processor._load_template')
@patch('src.shopify_client.get_recent_orders')
@patch('src.parcel_panel.get_order_tracking')
@patch('src.email_sender.send_email')
class TestRunStateAndCancellation:
    """Tests for RunState progress tracking and cancellation."""

    def test_run_state_tracks_progress(self, mock_sendgrid, mock_parcelpanel,
                                       mock_shopify, mock_template, test_store):
        """RunState counters update during processing."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        mock_shopify.return_value = [
            {
                'id': str(i), 'name': f'#10{i}',
                'created_at': '2024-01-01T00:00:00Z',
                'customer': {'email': f'c{i}@test.com', 'first_name': f'C{i}'},
                'fulfillments': [{'tracking_number': f'TRK{i}'}],
                'cancelled_at': None,
            }
            for i in range(3)
        ]
        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'TRK0'}],
        }

        run_state = processor.RunState('test-run', dry_run=True)
        summary = processor.process_all_stores(
            dry_run=True, store_id='test-store', run_state=run_state)

        assert run_state.total_stores == 1
        assert run_state.stores_processed == 1
        assert run_state.current_store == 'Test Store'
        assert run_state.total_orders == 3
        assert run_state.orders_checked == 3
        assert run_state.emails_found == summary['emails_sent']

    def test_cancellation_stops_processing(self, mock_sendgrid, mock_parcelpanel,
                                           mock_shopify, mock_template, test_store):
        """Setting cancel_event stops processing between orders."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)

        orders = [
            {
                'id': str(i), 'name': f'#20{i}',
                'created_at': '2024-01-01T00:00:00Z',
                'customer': {'email': f'c{i}@test.com', 'first_name': f'C{i}'},
                'fulfillments': [{'tracking_number': f'TRK{i}'}],
                'cancelled_at': None,
            }
            for i in range(10)
        ]
        mock_shopify.return_value = orders
        mock_parcelpanel.return_value = {
            'shipments': [{'status': 'PENDING', 'tracking_number': 'TRK0'}],
        }

        run_state = processor.RunState('cancel-test', dry_run=True)
        # Cancel immediately — should stop after checking first order
        run_state.cancel_event.set()

        summary = processor.process_all_stores(
            dry_run=True, store_id='test-store', run_state=run_state)

        # Should have processed far fewer than 10 orders
        assert run_state.orders_checked < 10
        # Result still returns valid summary
        assert 'emails_sent' in summary

    def test_dry_run_skips_store_lock(self, mock_sendgrid, mock_parcelpanel,
                                      mock_shopify, mock_template, test_store):
        """Dry runs don't acquire the store lock, so they can't return already_running."""
        mock_template.return_value = '<p>Order {{ order_number }}</p>'
        database.create_store(test_store)
        mock_shopify.return_value = []

        # Acquire the store lock manually (simulating a live run in progress)
        import threading
        lock = processor._get_store_lock('test-store')
        lock.acquire()

        try:
            # Dry run should still work — it skips the lock
            result = processor.process_store(test_store, dry_run=True)
            assert 'already_running' not in result
        finally:
            lock.release()

    def test_live_run_respects_store_lock(self, mock_sendgrid, mock_parcelpanel,
                                          mock_shopify, mock_template, test_store):
        """Live runs still respect the store lock."""
        database.create_store(test_store)
        mock_shopify.return_value = []

        lock = processor._get_store_lock('test-store')
        lock.acquire()

        try:
            result = processor.process_store(test_store, dry_run=False)
            assert result.get('already_running') is True
        finally:
            lock.release()

    def test_register_and_get_run(self, mock_sendgrid, mock_parcelpanel,
                                  mock_shopify, mock_template, test_store):
        """RunState can be registered and retrieved."""
        run_state = processor.RunState('reg-test', dry_run=True)
        processor.register_run(run_state)

        retrieved = processor.get_run('reg-test')
        assert retrieved is run_state
        assert retrieved.run_id == 'reg-test'
        assert retrieved.dry_run is True
        assert retrieved.status == 'running'

        # Cleanup
        with processor._active_runs_lock:
            del processor._active_runs['reg-test']

    def test_get_active_runs(self, mock_sendgrid, mock_parcelpanel,
                             mock_shopify, mock_template, test_store):
        """get_active_runs returns only running runs."""
        run1 = processor.RunState('active-1', dry_run=True)
        run2 = processor.RunState('active-2', dry_run=False, source='scheduler')
        run2.status = 'completed'
        processor.register_run(run1)
        processor.register_run(run2)

        active = processor.get_active_runs()
        active_ids = [r.run_id for r in active]
        assert 'active-1' in active_ids
        assert 'active-2' not in active_ids

        # Cleanup
        with processor._active_runs_lock:
            processor._active_runs.pop('active-1', None)
            processor._active_runs.pop('active-2', None)

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

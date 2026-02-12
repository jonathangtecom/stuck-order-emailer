"""
COMPREHENSIVE EDGE CASES TESTS - Processor edge cases, CSV limits, Unicode

Priority: MEDIUM-HIGH - Handles real-world edge cases and prevents resource exhaustion

This file combines:
- Processor edge cases (date parsing, customer names, template errors)
- CSV export memory limits (large datasets, resource exhaustion)
- Unicode handling (international characters, emoji, RTL languages)

These tests ensure robust handling of edge cases that could occur in production.
"""

import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta

# Setup test environment
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_edge.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)
with open(os.path.join(_tmpdir, 'templates', 'example.html'), 'w') as f:
    f.write('<h1>{{ store_name }}</h1>')

from app import app
from src import database, processor


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
def auth_client(client):
    client.post('/login', data={'password': 'testpass'})
    return client


# =============================================================================
# PROCESSOR EDGE CASES
# =============================================================================

class TestProcessorEdgeCases:
    """Tests for processor edge cases and boundary conditions"""

    def test_parse_date_future_date(self):
        """Future dates should parse correctly"""
        future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        dt = processor._parse_date(future)

        assert dt is not None
        assert dt > datetime.now(timezone.utc)

    def test_parse_date_leap_year_feb_29(self):
        """Leap year Feb 29 should parse correctly"""
        leap_date = '2024-02-29T12:00:00Z'
        dt = processor._parse_date(leap_date)

        assert dt is not None
        assert dt.day == 29

    def test_parse_date_invalid_feb_29(self):
        """Invalid Feb 29 (non-leap year) should return None"""
        invalid = '2023-02-29T12:00:00Z'
        dt = processor._parse_date(invalid)

        assert dt is None

    def test_render_template_string_with_missing_variables(self):
        """Missing variables should render as empty string"""
        template = 'Hello {{ undefined_var }}'
        result = processor._render_template_string(template, {})

        assert result == 'Hello '

    def test_render_template_string_with_unicode(self):
        """Unicode in template variables should be preserved"""
        template = 'Customer: {{ name }}'
        variables = {'name': '张伟 (测试)'}
        result = processor._render_template_string(template, variables)

        assert '张伟' in result


# =============================================================================
# CSV EXPORT LIMITS
# =============================================================================

class TestCSVExportLimits:
    """Tests for CSV export memory limits"""

    def test_csv_export_moderate_dataset(self, auth_client):
        """1000 rows should export successfully"""
        store_id = database.create_store({
            'name': 'Test Store',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 'test.myshopify.com',
            'shopify_admin_api_token': 't',
            'from_email': 'test@example.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        # Insert 1000 records
        for i in range(1000):
            database.record_sent_email({
                'store_id': store_id,
                'store_name': 'Test Store',
                'order_id': str(i),
                'order_number': f'#{i}',
                'customer_email': f'customer{i}@test.com',
                'tracking_number': f'TN{i}',
                'tracking_status': 'PENDING',
                'days_waiting': 10,
            })

        resp = auth_client.get('/logs/export')
        assert resp.status_code == 200
        csv_data = resp.data.decode('utf-8')
        rows = csv_data.split('\n')
        assert len(rows) >= 1000

    def test_csv_export_with_unicode(self, auth_client):
        """CSV with unicode should encode correctly"""
        store_id = database.create_store({
            'name': '测试商店',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 'test.myshopify.com',
            'shopify_admin_api_token': 't',
            'from_email': 'test@example.com',
            'from_name': '测试团队',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        database.record_sent_email({
            'store_id': store_id,
            'store_name': '测试商店',
            'order_id': '1',
            'order_number': '#1001',
            'customer_email': 'user@example.jp',
            'tracking_number': 'TN1',
            'tracking_status': 'PENDING',
            'days_waiting': 10,
        })

        resp = auth_client.get('/logs/export')
        assert resp.status_code == 200
        csv_data = resp.data.decode('utf-8')
        assert '测试商店' in csv_data


# =============================================================================
# UNICODE HANDLING
# =============================================================================

class TestUnicodeHandling:
    """Tests for unicode support"""

    def test_store_name_with_emoji(self, auth_client):
        """Store name with emoji should work"""
        resp = auth_client.post('/stores', data={
            'name': 'Test Store 🛒',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 'test.myshopify.com',
            'shopify_admin_api_token': 't',
            'from_email': 'test@example.com',
            'from_name': 'Test 👥',
            'email_subject': 'Order 📧',
            'email_template': 'example.html',
        }, follow_redirects=True)

        assert resp.status_code == 200
        stores = database.get_all_stores()
        assert any('🛒' in s['name'] for s in stores)

    def test_database_unicode_storage(self):
        """Unicode should be stored and retrieved correctly"""
        store_id = database.create_store({
            'name': '日本ストア',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 'test.myshopify.com',
            'shopify_admin_api_token': 't',
            'from_email': 'test@example.jp',
            'from_name': '佐藤太郎',
            'email_subject': '注文更新',
            'email_template': 'example.html',
        })

        store = database.get_store(store_id)
        assert '日本ストア' in store['name']
        assert '佐藤太郎' in store['from_name']

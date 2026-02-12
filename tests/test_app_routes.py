"""Integration tests for Flask routes in app.py"""
import os
import csv
import tempfile
import pytest
from io import StringIO

_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_routes.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)
with open(os.path.join(os.environ['TEMPLATES_PATH'], 'example.html'), 'w') as f:
    f.write('<h1>{{ store_name }}</h1>')

from app import app
from src import database


@pytest.fixture
def client():
    app.config['TESTING'] = True
    # Reset DB
    database.DATABASE_PATH = os.environ['DATABASE_PATH']
    if os.path.exists(database.DATABASE_PATH):
        os.remove(database.DATABASE_PATH)
    database.init_db()
    with app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Client with active session."""
    client.post('/login', data={'password': 'testpass'})
    return client


def _create_store(auth_client, name='Test Store'):
    return auth_client.post('/stores', data={
        'name': name,
        'parcel_panel_api_key': 'pp-key',
        'shopify_store_url': 'test.myshopify.com',
        'shopify_admin_api_token': 'shpat_test',
        'from_email': 'test@example.com',
        'from_name': 'Test Team',
        'email_subject': 'Order update',
        'email_template': 'example.html',
        'days_threshold': '8',
    }, follow_redirects=True)


class TestAuth:
    def test_unauthenticated_redirects(self, client):
        for path in ['/', '/stores', '/templates', '/logs', '/stores/new']:
            resp = client.get(path)
            assert resp.status_code == 302
            assert '/login' in resp.headers['Location']

    def test_api_templates_requires_auth(self, client):
        resp = client.get('/api/templates')
        assert resp.status_code == 302

    def test_login_wrong_password(self, client):
        resp = client.post('/login', data={'password': 'wrong'})
        assert resp.status_code == 200
        assert b'Invalid password' in resp.data

    def test_login_success(self, client):
        resp = client.post('/login', data={'password': 'testpass'})
        assert resp.status_code == 302

    def test_login_then_access(self, auth_client):
        resp = auth_client.get('/')
        assert resp.status_code == 200

    def test_logout(self, auth_client):
        auth_client.get('/logout')
        resp = auth_client.get('/')
        assert resp.status_code == 302

    def test_timing_safe_password(self, client):
        """FIXED: Password comparison now uses hmac.compare_digest."""
        import inspect
        from app import login
        source = inspect.getsource(login)
        assert 'hmac.compare_digest' in source


class TestDashboard:
    def test_empty_dashboard(self, auth_client):
        resp = auth_client.get('/')
        assert resp.status_code == 200
        assert b'stat-card' in resp.data

    def test_dashboard_shows_store_count(self, auth_client):
        _create_store(auth_client, 'Store A')
        resp = auth_client.get('/')
        assert b'Store A' in resp.data


class TestStoreCRUD:
    def test_create_store(self, auth_client):
        resp = _create_store(auth_client)
        assert resp.status_code == 200
        assert b'Test Store' in resp.data

    def test_create_missing_fields(self, auth_client):
        resp = auth_client.post('/stores', data={'name': 'Incomplete'})
        assert b'Missing required fields' in resp.data

    def test_create_invalid_email(self, auth_client):
        resp = auth_client.post('/stores', data={
            'name': 'Bad Email',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'not-an-email',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })
        assert b'Invalid from_email' in resp.data

    def test_edit_form_loads(self, auth_client):
        _create_store(auth_client)
        resp = auth_client.get('/stores/test-store/edit')
        assert resp.status_code == 200
        assert b'test.myshopify.com' in resp.data

    def test_edit_nonexistent(self, auth_client):
        resp = auth_client.get('/stores/nonexistent/edit', follow_redirects=True)
        assert b'Store not found' in resp.data

    def test_update_store(self, auth_client):
        _create_store(auth_client)
        resp = auth_client.post('/stores/test-store', data={
            'name': 'Test Store',
            'from_email': 'new@test.com',
            'from_name': 'New Team',
            'email_subject': 'Updated',
            'email_template': 'example.html',
            'days_threshold': '10',
        }, follow_redirects=True)
        assert b'Store updated' in resp.data

    def test_update_preserves_passwords_when_blank(self, auth_client):
        _create_store(auth_client)
        # Update with blank password fields
        auth_client.post('/stores/test-store', data={
            'name': 'Test Store',
            'parcel_panel_api_key': '',
            'shopify_admin_api_token': '',
            'from_email': 'test@example.com',
            'from_name': 'Test Team',
            'email_subject': 'Subject',
            'email_template': 'example.html',
            'days_threshold': '8',
        }, follow_redirects=True)
        store = database.get_store('test-store')
        assert store['parcel_panel_api_key'] == 'pp-key'
        assert store['shopify_admin_api_token'] == 'shpat_test'

    def test_toggle_store(self, auth_client):
        _create_store(auth_client)
        resp = auth_client.post('/stores/test-store/toggle')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['enabled'] is False

    def test_toggle_nonexistent(self, auth_client):
        resp = auth_client.post('/stores/nope/toggle')
        assert resp.status_code == 404

    def test_delete_store(self, auth_client):
        _create_store(auth_client)
        resp = auth_client.post('/stores/test-store/delete', follow_redirects=True)
        assert b'deleted' in resp.data

    def test_delete_nonexistent(self, auth_client):
        resp = auth_client.post('/stores/nope/delete', follow_redirects=True)
        assert b'Store not found' in resp.data


class TestTemplateAPI:
    def test_list_templates(self, auth_client):
        resp = auth_client.get('/api/templates')
        data = resp.get_json()
        assert 'example.html' in data['templates']

    def test_get_template(self, auth_client):
        resp = auth_client.get('/api/templates/example.html')
        data = resp.get_json()
        assert data['filename'] == 'example.html'
        assert 'store_name' in data['content']

    def test_save_template(self, auth_client):
        resp = auth_client.post('/api/templates/new-test.html',
                                json={'content': '<p>test</p>'})
        assert resp.get_json()['ok'] is True
        # Verify it's listed
        resp2 = auth_client.get('/api/templates')
        assert 'new-test.html' in resp2.get_json()['templates']

    def test_delete_template(self, auth_client):
        auth_client.post('/api/templates/to-delete.html',
                         json={'content': 'x'})
        resp = auth_client.delete('/api/templates/to-delete.html')
        assert resp.get_json()['ok'] is True

    def test_bad_filename_rejected(self, auth_client):
        resp = auth_client.get('/api/templates/../etc/passwd')
        assert resp.status_code in (400, 404)

    def test_non_html_rejected(self, auth_client):
        resp = auth_client.get('/api/templates/script.js')
        assert resp.status_code == 400

    def test_preview_renders_variables(self, auth_client):
        resp = auth_client.post('/api/templates/preview',
                                json={'content': '{{ customer_name }} {{ order_number }}'})
        assert resp.status_code == 200
        assert b'John' in resp.data
        assert b'#1042' in resp.data

    def test_preview_bad_syntax(self, auth_client):
        resp = auth_client.post('/api/templates/preview',
                                json={'content': '{{ broken {% if %}'})
        assert resp.status_code == 400

    def test_preview_no_content(self, auth_client):
        resp = auth_client.post('/api/templates/preview', json={})
        assert resp.status_code == 400

    def test_path_traversal_via_dots(self, auth_client):
        """Test that path traversal attempts are blocked."""
        resp = auth_client.get('/api/templates/..%2F..%2Fetc%2Fpasswd')
        assert resp.status_code in (400, 404)

    def test_filename_with_spaces_rejected(self, auth_client):
        resp = auth_client.post('/api/templates/my%20template.html',
                                json={'content': 'x'})
        assert resp.status_code == 400


class TestLogs:
    def _insert_test_emails(self, n=5):
        store_id = database.create_store({
            'name': 'Log Store', 'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com', 'shopify_admin_api_token': 't',
            'from_email': 'a@b.com', 'from_name': 'T',
            'email_subject': 'S', 'email_template': 'example.html',
        })
        for i in range(n):
            database.record_sent_email({
                'store_id': store_id, 'store_name': 'Log Store',
                'order_id': str(i), 'order_number': f'#{i}',
                'customer_email': f'c{i}@t.com',
                'tracking_number': f'YT{i}',
                'tracking_status': 'PENDING',
                'days_waiting': 10,
            })
        return store_id

    def test_logs_page(self, auth_client):
        self._insert_test_emails()
        resp = auth_client.get('/logs')
        assert resp.status_code == 200
        assert b'Log Store' in resp.data

    def test_logs_pagination(self, auth_client):
        self._insert_test_emails(75)
        resp = auth_client.get('/logs')
        assert b'Page 1 of 2' in resp.data

    def test_logs_filter_by_store(self, auth_client):
        store_id = self._insert_test_emails()
        resp = auth_client.get(f'/logs?store={store_id}')
        assert resp.status_code == 200

    def test_csv_export(self, auth_client):
        self._insert_test_emails()
        resp = auth_client.get('/logs/export')
        assert resp.status_code == 200
        assert resp.content_type == 'text/csv; charset=utf-8'
        assert b'Customer Email' in resp.data

    def test_csv_has_correct_rows(self, auth_client):
        self._insert_test_emails(3)
        resp = auth_client.get('/logs/export')
        reader = csv.reader(StringIO(resp.data.decode()))
        rows = list(reader)
        assert len(rows) == 4  # header + 3 data rows

    def test_logs_empty(self, auth_client):
        resp = auth_client.get('/logs')
        assert b'No emails sent' in resp.data


class TestApiRun:
    def test_run_from_localhost(self, auth_client):
        # Flask test client uses 127.0.0.1 by default
        resp = auth_client.post('/api/run')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'processed' in data

    def test_run_get_method_not_allowed(self, auth_client):
        resp = auth_client.get('/api/run')
        assert resp.status_code == 405


class TestSecurityHeaders:
    def test_csp_header_present(self, auth_client):
        """FIXED: Content-Security-Policy header is now set."""
        resp = auth_client.get('/')
        assert 'Content-Security-Policy' in resp.headers
        assert "default-src 'self'" in resp.headers['Content-Security-Policy']

    def test_x_content_type_options_present(self, auth_client):
        """FIXED: X-Content-Type-Options header is now set."""
        resp = auth_client.get('/')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_x_frame_options_present(self, auth_client):
        """FIXED: X-Frame-Options header is now set."""
        resp = auth_client.get('/')
        assert resp.headers.get('X-Frame-Options') == 'DENY'


class TestXSSVulnerabilities:
    def test_store_name_xss_prevented(self, auth_client):
        """FIXED: store.name/id now use data-* attributes instead of inline JS.
        Jinja2 HTML-escapes data attributes safely — no JS injection possible."""
        auth_client.post('/stores', data={
            'name': "test');alert(1);('",
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'a@b.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        }, follow_redirects=True)
        resp = auth_client.get('/stores')
        html_content = resp.data.decode()
        # Values are now in data-store-name attributes, safely HTML-escaped
        assert 'data-store-name=' in html_content
        # The old vulnerable pattern (inline JS string interpolation) should be gone
        assert "deleteStore('" not in html_content


class TestCSVInjection:
    def test_csv_injection_sanitized(self, auth_client):
        """FIXED: CSV export sanitizes values starting with =, +, -, @."""
        store_id = database.create_store({
            'name': '=cmd|/C calc|!A0',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'a@b.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })
        database.record_sent_email({
            'store_id': store_id, 'store_name': '=cmd|/C calc|!A0',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'c@t.com',
        })
        resp = auth_client.get('/logs/export')
        content = resp.data.decode()
        # FIXED: Formula char is prefixed with ' to prevent Excel injection
        assert "'=cmd" in content
        # Raw formula should NOT appear
        lines = content.split('\n')
        data_line = lines[1]  # first data row
        assert not data_line.startswith('"=cmd')


class TestSafeTemplatePath:
    def test_prefix_matching_bug(self, auth_client):
        """BUG: _safe_template_path uses startswith which can match
        directories with similar prefixes like 'templates_evil'."""
        from app import _safe_template_path, TEMPLATES_PATH
        # If TEMPLATES_PATH is /tmp/xxx/templates, a file at
        # /tmp/xxx/templates_evil/hack.html would match startswith
        # This test documents the vulnerability
        import app
        original = app.TEMPLATES_PATH
        try:
            app.TEMPLATES_PATH = '/tmp/test_templates'
            # A filename that resolves outside but shares prefix
            # The regex check prevents this in practice, but _safe_template_path alone is buggy
            result = _safe_template_path('valid.html')
            # Can't fully test without creating dirs, but document the logic flaw
        finally:
            app.TEMPLATES_PATH = original

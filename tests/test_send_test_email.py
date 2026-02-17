"""Tests for the Send Test Email feature."""
import os
import tempfile
import pytest
from unittest.mock import patch

# Set up test environment
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_send_email.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)

from app import app
from src import database

CSRF_TOKEN = 'test-csrf-token'


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
def logged_in_client(client):
    """Return a logged-in test client."""
    with client.session_transaction() as sess:
        sess['csrf_token'] = CSRF_TOKEN
    client.post('/login', data={'password': 'testpass', 'csrf_token': CSRF_TOKEN})
    return client


class TestSendTestEmail:
    """Tests for /api/templates/send-test endpoint."""

    def test_send_test_email_success(self, logged_in_client, monkeypatch):
        """Test successful test email sending."""
        # Mock SendGrid API key
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.test-key-123')

        # Mock send_email function
        with patch('src.email_sender.send_email', return_value=True) as mock_send:
            response = logged_in_client.post(
                '/api/templates/send-test',
                json={
                    'content': '<p>Hi {{ customer_name }}</p>',
                    'to_email': 'test@example.com',
                    'from_email': 'support@store.com',
                    'from_name': 'Test Store',
                    'subject': 'Order {{ order_number }}',
                },
                headers={'X-CSRF-Token': CSRF_TOKEN},
            )

            assert response.status_code == 200
            data = response.get_json()
            assert data['ok'] is True
            assert 'sent' in data['message'].lower()

            # Verify send_email was called with correct parameters
            assert mock_send.called
            call_args = mock_send.call_args[1]
            assert call_args['to_email'] == 'test@example.com'
            assert call_args['from_email'] == 'support@store.com'
            assert call_args['from_name'] == 'Test Store'
            assert 'John Doe' in call_args['html_content']  # Sample data rendered
            assert call_args['subject'] == 'Order #1042'  # Template rendered

    def test_send_test_email_missing_fields(self, logged_in_client):
        """Test validation for missing required fields."""
        response = logged_in_client.post(
            '/api/templates/send-test',
            json={
                'content': '<p>Test</p>',
                'to_email': 'test@example.com',
                # Missing from_email, from_name, subject
            },
            headers={'X-CSRF-Token': CSRF_TOKEN},
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_send_test_email_invalid_email(self, logged_in_client, monkeypatch):
        """Test validation for invalid email formats."""
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.test-key-123')

        response = logged_in_client.post(
            '/api/templates/send-test',
            json={
                'content': '<p>Test</p>',
                'to_email': 'invalid-email',
                'from_email': 'support@store.com',
                'from_name': 'Store',
                'subject': 'Test',
            },
            headers={'X-CSRF-Token': CSRF_TOKEN},
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'email format' in data['error'].lower()

    def test_send_test_email_no_sendgrid_key(self, logged_in_client, monkeypatch):
        """Test error when SENDGRID_API_KEY is not configured."""
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.your-key-here')  # Placeholder value

        response = logged_in_client.post(
            '/api/templates/send-test',
            json={
                'content': '<p>Test</p>',
                'to_email': 'test@example.com',
                'from_email': 'support@store.com',
                'from_name': 'Store',
                'subject': 'Test',
            },
            headers={'X-CSRF-Token': CSRF_TOKEN},
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'SENDGRID_API_KEY' in data['error']

    def test_send_test_email_template_error(self, logged_in_client, monkeypatch):
        """Test handling of template rendering errors."""
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.test-key-123')

        response = logged_in_client.post(
            '/api/templates/send-test',
            json={
                'content': '<p>{{ undefined_var | bad_filter }}</p>',  # Bad Jinja2 syntax
                'to_email': 'test@example.com',
                'from_email': 'support@store.com',
                'from_name': 'Store',
                'subject': 'Test',
            },
            headers={'X-CSRF-Token': CSRF_TOKEN},
        )

        assert response.status_code == 500
        data = response.get_json()
        assert 'error' in data

    def test_send_test_email_sendgrid_failure(self, logged_in_client, monkeypatch):
        """Test handling when SendGrid fails to send."""
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.test-key-123')

        # Mock send_email to return False (failure)
        with patch('src.email_sender.send_email', return_value=False):
            response = logged_in_client.post(
                '/api/templates/send-test',
                json={
                    'content': '<p>Test</p>',
                    'to_email': 'test@example.com',
                    'from_email': 'support@store.com',
                    'from_name': 'Store',
                    'subject': 'Test',
                },
                headers={'X-CSRF-Token': CSRF_TOKEN},
            )

            assert response.status_code == 500
            data = response.get_json()
            assert 'failed' in data['error'].lower()

    def test_send_test_email_requires_auth(self, client):
        """Test that endpoint requires authentication."""
        response = client.post(
            '/api/templates/send-test',
            json={
                'content': '<p>Test</p>',
                'to_email': 'test@example.com',
                'from_email': 'support@store.com',
                'from_name': 'Store',
                'subject': 'Test',
            },
        )

        # Should redirect to login or return 401/403
        assert response.status_code in (302, 401, 403)

    def test_send_test_email_subject_with_variables(self, logged_in_client, monkeypatch):
        """Test that subject line renders Jinja2 variables."""
        monkeypatch.setenv('SENDGRID_API_KEY', 'SG.test-key-123')

        with patch('src.email_sender.send_email', return_value=True) as mock_send:
            response = logged_in_client.post(
                '/api/templates/send-test',
                json={
                    'content': '<p>Hi {{ customer_name }}</p>',
                    'to_email': 'test@example.com',
                    'from_email': 'support@store.com',
                    'from_name': 'Store',
                    'subject': 'Your order {{ order_number }} - {{ days_waiting }} days',
                },
                headers={'X-CSRF-Token': CSRF_TOKEN},
            )

            assert response.status_code == 200

            # Verify subject was rendered with sample data
            call_args = mock_send.call_args[1]
            assert call_args['subject'] == 'Your order #1042 - 10 days'

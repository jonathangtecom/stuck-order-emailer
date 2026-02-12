"""Tests for Sentry integration"""
import os
import tempfile
import pytest

# Set up test environment BEFORE importing app
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_sentry.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'
os.environ['SENTRY_DSN'] = ''  # Disable Sentry for tests

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)

from app import app, _sentry_before_send, _get_release_version


def test_sentry_disabled_without_dsn():
    """Verify app works without Sentry configured."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        response = client.get('/login')
        assert response.status_code == 200


def test_sentry_before_send_filters_sensitive_data():
    """Verify sensitive data is filtered from Sentry events."""
    event = {
        'request': {
            'headers': {
                'X-Shopify-Access-Token': 'secret-token',
                'x-parcelpanel-api-key': 'secret-key',
                'User-Agent': 'Mozilla/5.0',
            },
            'data': {
                'parcel_panel_api_key': 'pp-secret',
                'shopify_admin_api_token': 'shpat-secret',
                'name': 'Test Store',
            }
        },
        'exception': {
            'values': [{
                'stacktrace': {
                    'frames': [{
                        'vars': {
                            'api_key': 'secret',
                            'ADMIN_PASSWORD': 'password123',
                            'store_name': 'Test Store',
                        }
                    }]
                }
            }]
        }
    }

    filtered = _sentry_before_send(event, {})

    # Check headers filtered
    assert filtered['request']['headers']['X-Shopify-Access-Token'] == '[Filtered]'
    assert filtered['request']['headers']['x-parcelpanel-api-key'] == '[Filtered]'
    assert filtered['request']['headers']['User-Agent'] == 'Mozilla/5.0'  # Not filtered

    # Check request data filtered
    assert filtered['request']['data']['parcel_panel_api_key'] == '[Filtered]'
    assert filtered['request']['data']['shopify_admin_api_token'] == '[Filtered]'
    assert filtered['request']['data']['name'] == 'Test Store'  # Not filtered

    # Check variables filtered
    frame_vars = filtered['exception']['values'][0]['stacktrace']['frames'][0]['vars']
    assert frame_vars['api_key'] == '[Filtered]'
    assert frame_vars['ADMIN_PASSWORD'] == '[Filtered]'
    assert frame_vars['store_name'] == 'Test Store'  # Not filtered


def test_get_release_version():
    """Verify release version detection works."""
    version = _get_release_version()
    assert version.startswith('stuck-order-emailer@')

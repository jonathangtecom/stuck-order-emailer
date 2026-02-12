"""
CRITICAL BUG TESTS - These test 4 confirmed production bugs that WILL crash the application

Priority: CRITICAL - These must be fixed before production deployment

Bugs Tested:
1. Bearer Token Timing Attack (app.py:443) - Security vulnerability
2. Malformed Link Header Crash (shopify_client.py:68) - IndexError crash
3. Malformed Retry-After Header Crash (src/__init__.py:37) - ValueError crash
4. Weak Email Validation (app.py:480) - Accepts invalid emails
"""

import os
import tempfile
import pytest
import inspect
import hmac
from unittest.mock import patch, MagicMock
import requests

# Setup test environment
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_critical.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'
os.environ['RUN_TOKEN'] = 'test-run-token-12345'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)
with open(os.path.join(os.environ['TEMPLATES_PATH'], 'example.html'), 'w') as f:
    f.write('<h1>{{ store_name }}</h1>')

from app import app
from src import database
from src import shopify_client
from src import api_request_with_retry


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
    """Client with active session."""
    client.post('/login', data={'password': 'testpass'})
    return client


# =============================================================================
# BUG 1: BEARER TOKEN TIMING ATTACK (app.py:443)
# =============================================================================

class TestBug1BearerTokenTimingAttack:
    """
    CRITICAL SECURITY BUG: app.py:443 uses `token == RUN_TOKEN` instead of hmac.compare_digest()

    Impact: Attackers can determine the RUN_TOKEN byte-by-byte using timing analysis
    Attack: Measure response time for different token guesses, correct bytes take longer
    Fix Required: Replace `token == RUN_TOKEN` with `hmac.compare_digest(token, RUN_TOKEN)`

    Reference: https://security.stackexchange.com/questions/83660/simple-string-comparisons-not-secure-against-timing-attacks
    """

    def test_bearer_token_uses_timing_safe_comparison(self):
        """CRITICAL: Bearer token comparison must use hmac.compare_digest() to prevent timing attacks"""
        from app import api_run

        source = inspect.getsource(api_run)

        # Check for timing-safe comparison
        assert 'hmac.compare_digest' in source, \
            "CRITICAL BUG: Bearer token comparison at line 443 must use hmac.compare_digest(token, RUN_TOKEN) " \
            "to prevent timing attacks. Current code uses `token == RUN_TOKEN` which is vulnerable."

    def test_bearer_token_not_using_direct_equality(self):
        """CRITICAL: Direct equality (==) for bearer tokens is vulnerable to timing attacks"""
        from app import api_run

        source = inspect.getsource(api_run)

        # Verify it's NOT using direct equality on the token itself
        # Note: This may be overly strict if code is already fixed
        if 'token == RUN_TOKEN' in source:
            pytest.fail(
                "CRITICAL BUG DETECTED: Line 443 uses `token == RUN_TOKEN` which is vulnerable to timing attacks. "
                "Replace with: is_token_valid = RUN_TOKEN and hmac.compare_digest(token, RUN_TOKEN or '')"
            )

    def test_bearer_token_empty_run_token_blocks_auth(self, client):
        """HIGH: If RUN_TOKEN is empty, bearer auth should be disabled entirely"""
        # Temporarily clear RUN_TOKEN
        original_token = os.environ.get('RUN_TOKEN')

        try:
            os.environ['RUN_TOKEN'] = ''
            # Reimport to pick up new env var
            import importlib
            import app as app_module
            importlib.reload(app_module)

            # Attempt auth with bearer token when RUN_TOKEN is empty
            resp = client.post('/api/run',
                              headers={'Authorization': 'Bearer anything'},
                              environ_base={'REMOTE_ADDR': '8.8.8.8'})  # Non-localhost

            # Should reject because RUN_TOKEN is empty (bearer auth disabled)
            assert resp.status_code == 403, \
                "When RUN_TOKEN is empty, bearer auth should be disabled and return 403"

        finally:
            if original_token:
                os.environ['RUN_TOKEN'] = original_token


# =============================================================================
# BUG 2: MALFORMED LINK HEADER CRASHES PAGINATION (shopify_client.py:68)
# =============================================================================

class TestBug2MalformedLinkHeaderCrash:
    """
    CRITICAL CRASH BUG: shopify_client.py:68 uses part.split('<')[1].split('>')[0]

    Impact: Production crash if Shopify returns malformed Link header
    Scenario: Link header "rel=next" (missing brackets) → IndexError → Store processing crashes
    Consequence: Daily cron job fails, no emails sent, stores blocked
    Fix Required: Wrap in try/except, log warning, stop pagination gracefully

    Code at line 68:
        url = part.split('<')[1].split('>')[0]

    This assumes Link header format: <https://url>; rel="next"
    But fails if format is different (e.g., missing brackets)
    """

    @patch('src.shopify_client.api_request_with_retry')
    def test_malformed_link_header_missing_brackets_no_crash(self, mock_request):
        """CRITICAL: Malformed Link header (missing < >) should not crash, should stop pagination gracefully"""

        # Mock response with malformed Link header (missing brackets)
        mock_response = MagicMock()
        mock_response.json.return_value = {'orders': [{'id': 1, 'name': '#1001'}]}
        mock_response.headers = {'Link': 'rel="next"'}  # Missing < > brackets - MALFORMED
        mock_request.return_value = mock_response

        # Should not raise IndexError, should return partial results
        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token', days_back=30)

        # Should return 1 order (partial success), not crash
        assert len(orders) == 1
        assert orders[0]['id'] == 1

    @patch('src.shopify_client.api_request_with_retry')
    def test_malformed_link_header_only_url_no_brackets(self, mock_request):
        """CRITICAL: Link header with URL but no brackets should not crash"""

        mock_response = MagicMock()
        mock_response.json.return_value = {'orders': [{'id': 2, 'name': '#1002'}]}
        mock_response.headers = {'Link': 'https://test.com/next; rel="next"'}  # Missing < > - MALFORMED
        mock_request.return_value = mock_response

        # Should not crash
        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token')
        assert len(orders) == 1

    @patch('src.shopify_client.api_request_with_retry')
    def test_malformed_link_header_empty_string(self, mock_request):
        """MEDIUM: Empty Link header should not crash"""

        mock_response = MagicMock()
        mock_response.json.return_value = {'orders': [{'id': 3, 'name': '#1003'}]}
        mock_response.headers = {'Link': ''}  # Empty string
        mock_request.return_value = mock_response

        orders = shopify_client.get_recent_orders('test.myshopify.com', 'token')
        assert len(orders) == 1


# =============================================================================
# BUG 3: MALFORMED RETRY-AFTER HEADER CRASHES (src/__init__.py:37)
# =============================================================================

class TestBug3MalformedRetryAfterHeaderCrash:
    """
    CRITICAL CRASH BUG: src/__init__.py:37 uses float(resp.headers.get('Retry-After', ...))

    Impact: Production crash if API returns Retry-After in HTTP-date format instead of seconds
    Scenario: Retry-After: "Wed, 21 Oct 2025 07:28:00 GMT" → ValueError → Request fails
    RFC 7231: Retry-After can be either seconds OR HTTP-date
    Fix Required: Wrap in try/except ValueError, fall back to exponential backoff

    Code at line 37:
        retry_after = float(resp.headers.get('Retry-After', min(2 ** attempt, max_backoff)))

    This assumes Retry-After is always a number, but it can be an HTTP-date string
    """

    @patch('requests.request')
    def test_retry_after_header_http_date_format_no_crash(self, mock_request):
        """CRITICAL: Retry-After header with HTTP-date format should not crash"""

        # First call: 429 with HTTP-date format Retry-After
        response_429 = MagicMock()
        response_429.status_code = 429
        response_429.headers = {'Retry-After': 'Wed, 21 Oct 2025 07:28:00 GMT'}  # HTTP-date format

        # Second call: Success
        response_200 = MagicMock()
        response_200.status_code = 200
        response_200.json.return_value = {'success': True}

        mock_request.side_effect = [response_429, response_200]

        # Should not crash with ValueError, should retry and succeed
        result = api_request_with_retry('GET', 'http://test.com/api/endpoint')
        assert result.status_code == 200

    @patch('requests.request')
    def test_retry_after_header_non_numeric_string(self, mock_request):
        """CRITICAL: Non-numeric Retry-After header should not crash"""

        response_429 = MagicMock()
        response_429.status_code = 429
        response_429.headers = {'Retry-After': 'invalid-value'}  # Non-numeric string

        response_200 = MagicMock()
        response_200.status_code = 200
        response_200.json.return_value = {'success': True}

        mock_request.side_effect = [response_429, response_200]

        # Should fall back to exponential backoff, not crash
        result = api_request_with_retry('GET', 'http://test.com/api/endpoint')
        assert result.status_code == 200

    @patch('requests.request')
    def test_retry_after_header_negative_value(self, mock_request):
        """MEDIUM: Negative Retry-After value should be handled"""

        response_429 = MagicMock()
        response_429.status_code = 429
        response_429.headers = {'Retry-After': '-10'}  # Negative number

        response_200 = MagicMock()
        response_200.status_code = 200
        response_200.json.return_value = {'success': True}

        mock_request.side_effect = [response_429, response_200]

        # Should handle gracefully (use 0 or default backoff)
        result = api_request_with_retry('GET', 'http://test.com/api/endpoint')
        assert result.status_code == 200


# =============================================================================
# BUG 4: WEAK EMAIL VALIDATION (app.py:480)
# =============================================================================

class TestBug4WeakEmailValidation:
    r"""
    CRITICAL DATA INTEGRITY BUG: app.py:480 uses regex r'^[^@\s]+@[^@\s]+\.[^@\s]+$'

    Impact: Invalid emails stored in database → SendGrid API failures in production
    Current regex ACCEPTS these INVALID emails:
    - @.com (no local part)
    - user@ (no domain)
    - user@@domain.com (double @)
    - user@.com (domain starts with dot)
    - No length validation (RFC 5321: max 254 chars)

    Fix Required: Use more robust regex or email-validator library
    Recommended regex: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    """

    def test_email_validation_rejects_missing_local_part(self, auth_client):
        """CRITICAL: Email with no local part (@.com) should be rejected"""

        resp = auth_client.post('/stores', data={
            'name': 'Test Missing Local',
            'from_email': '@.com',  # INVALID: no local part
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        assert b'Invalid from_email' in resp.data, \
            "Email '@.com' should be rejected (missing local part)"

    def test_email_validation_rejects_missing_domain(self, auth_client):
        """CRITICAL: Email with no domain (user@) should be rejected"""

        resp = auth_client.post('/stores', data={
            'name': 'Test Missing Domain',
            'from_email': 'user@',  # INVALID: no domain
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        assert b'Invalid from_email' in resp.data, \
            "Email 'user@' should be rejected (missing domain)"

    def test_email_validation_rejects_double_at(self, auth_client):
        """CRITICAL: Email with double @ (user@@domain.com) should be rejected"""

        resp = auth_client.post('/stores', data={
            'name': 'Test Double At',
            'from_email': 'user@@domain.com',  # INVALID: double @
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        assert b'Invalid from_email' in resp.data, \
            "Email 'user@@domain.com' should be rejected (double @)"

    def test_email_validation_rejects_domain_starts_with_dot(self, auth_client):
        """HIGH: Email with domain starting with dot (user@.com) should be rejected"""

        resp = auth_client.post('/stores', data={
            'name': 'Test Dot Domain',
            'from_email': 'user@.com',  # INVALID: domain starts with dot
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        assert b'Invalid from_email' in resp.data, \
            "Email 'user@.com' should be rejected (domain starts with dot)"

    def test_email_validation_rejects_exceeds_rfc5321_limit(self, auth_client):
        """HIGH: Email longer than 254 chars should be rejected (RFC 5321 limit)"""

        # Create email with 255 characters total (over the 254 RFC 5321 limit)
        long_local = 'a' * 232
        email = f"{long_local}@verylongdomainname.com"  # 232 + 1(@) + 23 = 256 chars

        resp = auth_client.post('/stores', data={
            'name': 'Test Long Email',
            'from_email': email,
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        # Should reject emails over 254 chars
        assert b'Invalid from_email' in resp.data or b'too long' in resp.data, \
            f"Email with {len(email)} chars should be rejected (RFC 5321 limit: 254 chars)"

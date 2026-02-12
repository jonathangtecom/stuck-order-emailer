"""Unit tests for src/__init__.py api_request_with_retry"""
import os
import pytest
from unittest.mock import patch, MagicMock
import requests

from src import api_request_with_retry


class TestApiRetry:
    def test_success_on_first_try(self):
        with patch('src.requests.request') as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.raise_for_status = MagicMock()
            mock_req.return_value = mock_resp

            result = api_request_with_retry('GET', 'http://example.com')
            assert result == mock_resp
            assert mock_req.call_count == 1

    def test_retries_on_network_error(self):
        with patch('src.requests.request') as mock_req, \
             patch('src.time.sleep'):
            mock_req.side_effect = [
                requests.ConnectionError("fail"),
                requests.ConnectionError("fail"),
                MagicMock(status_code=200, raise_for_status=MagicMock()),
            ]
            result = api_request_with_retry('GET', 'http://example.com')
            assert result is not None
            assert mock_req.call_count == 3

    def test_raises_after_max_retries(self):
        with patch('src.requests.request') as mock_req, \
             patch('src.time.sleep'):
            mock_req.side_effect = requests.ConnectionError("fail")

            with pytest.raises(requests.ConnectionError):
                api_request_with_retry('GET', 'http://example.com', max_retries=3)
            assert mock_req.call_count == 3

    def test_429_rate_limit_retries(self):
        with patch('src.requests.request') as mock_req, \
             patch('src.time.sleep'):
            rate_limited = MagicMock()
            rate_limited.status_code = 429
            rate_limited.headers = {'Retry-After': '1'}

            success = MagicMock()
            success.status_code = 200
            success.raise_for_status = MagicMock()

            mock_req.side_effect = [rate_limited, success]
            result = api_request_with_retry('GET', 'http://example.com')
            assert result == success

    def test_429_exhausts_retries_raises(self):
        """FIXED: If all retries are 429, function now raises instead of returning None."""
        with patch('src.requests.request') as mock_req, \
             patch('src.time.sleep'):
            rate_limited = MagicMock()
            rate_limited.status_code = 429
            rate_limited.headers = {}

            mock_req.return_value = rate_limited
            with pytest.raises(requests.HTTPError):
                api_request_with_retry('GET', 'http://example.com', max_retries=3)

    def test_no_retry_on_4xx_client_error(self):
        """FIXED: 4xx errors (except 429) are not retried — they'll never succeed."""
        with patch('src.requests.request') as mock_req, \
             patch('src.time.sleep'):
            error_resp = MagicMock()
            error_resp.status_code = 401
            error_resp.raise_for_status.side_effect = requests.HTTPError(
                "401 Unauthorized", response=error_resp
            )

            mock_req.return_value = error_resp
            with pytest.raises(requests.HTTPError):
                api_request_with_retry('GET', 'http://example.com', max_retries=3)
            # FIXED: only 1 call — no retries on client errors
            assert mock_req.call_count == 1


class TestParcelPanel:
    def test_get_stuck_shipments(self):
        from src.parcel_panel import get_stuck_shipments
        data = {
            'shipments': [
                {'status': 'PENDING', 'tracking_number': 'YT1'},
                {'status': 'IN_TRANSIT', 'tracking_number': 'YT2'},
                {'status': 'INFO_RECEIVED', 'tracking_number': 'YT3'},
                {'status': 'DELIVERED', 'tracking_number': 'YT4'},
            ]
        }
        stuck = get_stuck_shipments(data)
        assert len(stuck) == 2
        assert stuck[0]['tracking_number'] == 'YT1'
        assert stuck[1]['tracking_number'] == 'YT3'

    def test_get_stuck_shipments_none_input(self):
        from src.parcel_panel import get_stuck_shipments
        assert get_stuck_shipments(None) == []
        assert get_stuck_shipments({}) == []
        assert get_stuck_shipments({'shipments': []}) == []

    def test_get_stuck_shipments_case_insensitive(self):
        from src.parcel_panel import get_stuck_shipments
        data = {'shipments': [{'status': 'pending'}, {'status': 'info_received'}]}
        stuck = get_stuck_shipments(data)
        assert len(stuck) == 2

    def test_get_tracking_url(self):
        from src.parcel_panel import get_tracking_url
        assert get_tracking_url({'tracking_link': 'http://track.it'}) == 'http://track.it'
        assert get_tracking_url(None) == ''
        assert get_tracking_url({}) == ''


class TestProcessor:
    def test_parse_date_iso_with_tz(self):
        from src.processor import _parse_date
        dt = _parse_date('2024-01-15T10:30:00-05:00')
        assert dt is not None
        assert dt.year == 2024

    def test_parse_date_iso_without_tz(self):
        from src.processor import _parse_date
        dt = _parse_date('2024-01-15T10:30:00')
        assert dt is not None
        assert dt.tzinfo is not None  # Should default to UTC

    def test_parse_date_empty(self):
        from src.processor import _parse_date
        assert _parse_date('') is None
        assert _parse_date(None) is None

    def test_parse_date_invalid(self):
        from src.processor import _parse_date
        assert _parse_date('not-a-date') is None
        assert _parse_date('abc123') is None

    def test_render_template_string(self):
        from src.processor import _render_template_string
        result = _render_template_string(
            'Hello {{ name }}, order {{ num }}',
            {'name': 'Alice', 'num': '#123'}
        )
        assert result == 'Hello Alice, order #123'

    def test_render_template_missing_var(self):
        from src.processor import _render_template_string
        result = _render_template_string('Hello {{ name }}', {})
        assert result == 'Hello '

    def test_render_template_bad_syntax(self):
        from src.processor import _render_template_string
        with pytest.raises(Exception):
            _render_template_string('{{ broken {% if %}', {})

    def test_load_template_traversal(self, tmp_path):
        from src.processor import _load_template
        import src.processor as proc
        proc.TEMPLATES_PATH = str(tmp_path / 'templates')
        os.makedirs(proc.TEMPLATES_PATH, exist_ok=True)

        secret = tmp_path / 'secret.txt'
        secret.write_text('secret data')

        result = _load_template('../secret.txt')
        assert result is None

    def test_load_template_nonexistent(self, tmp_path):
        from src.processor import _load_template
        import src.processor as proc
        proc.TEMPLATES_PATH = str(tmp_path / 'templates')
        os.makedirs(proc.TEMPLATES_PATH, exist_ok=True)

        result = _load_template('nope.html')
        assert result is None

import time
import logging
from datetime import datetime, timedelta, timezone

from src import api_request_with_retry

logger = logging.getLogger(__name__)

API_VERSION = '2024-01'


def _normalize_store_url(store_url):
    """Normalize store URL to a full myshopify.com hostname.

    Accepts: 'my-store', 'my-store.myshopify.com', or 'https://my-store.myshopify.com'.
    Returns: 'my-store.myshopify.com'
    """
    url = store_url.strip().rstrip('/')
    if url.startswith('https://'):
        url = url[len('https://'):]
    if url.startswith('http://'):
        url = url[len('http://'):]
    if '.' not in url:
        url = f'{url}.myshopify.com'
    return url


def get_recent_orders(store_url, api_token, days_back=30):
    """Fetch recent orders (shipped and unshipped) from a Shopify store.

    Returns a list of order dicts with: id, name, created_at, customer,
    fulfillment_status, fulfillments.
    Handles pagination via Link headers.
    """
    store_host = _normalize_store_url(store_url)
    headers = {
        'X-Shopify-Access-Token': api_token,
        'Content-Type': 'application/json',
    }

    created_at_min = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime('%Y-%m-%dT%H:%M:%S%z')

    url = f"https://{store_host}/admin/api/{API_VERSION}/orders.json"
    params = {
        'status': 'any',
        'fulfillment_status': 'any',
        'created_at_min': created_at_min,
        'limit': 250,
        'fields': 'id,name,created_at,customer,fulfillment_status,fulfillments,cancelled_at,shipping_address',
    }

    all_orders = []

    while url:
        resp = api_request_with_retry('GET', url, headers=headers, params=params)
        data = resp.json()
        orders = data.get('orders', [])
        all_orders.extend(orders)

        # Follow pagination via Link header
        url = None
        params = None  # Subsequent pages carry all params in the URL
        link_header = resp.headers.get('Link', '')
        if 'rel="next"' in link_header:
            for part in link_header.split(','):
                part = part.strip()
                if 'rel="next"' in part:
                    try:
                        url = part.split('<')[1].split('>')[0]
                        break
                    except IndexError:
                        logger.warning("Malformed Link header: %s", link_header)
                        # Stop pagination gracefully on malformed header
                        break

        # Small delay to respect Shopify rate limits
        time.sleep(0.5)

    logger.info("Fetched %d orders from %s", len(all_orders), store_host)
    return all_orders


def get_customer_for_order(store_url, api_token, order_id):
    """Get customer email and first name for a specific order.

    Returns dict with 'email' and 'first_name', or None if not found.
    """
    store_host = _normalize_store_url(store_url)
    headers = {
        'X-Shopify-Access-Token': api_token,
        'Content-Type': 'application/json',
    }

    url = f"https://{store_host}/admin/api/{API_VERSION}/orders/{order_id}.json"
    params = {'fields': 'id,customer'}

    try:
        resp = api_request_with_retry('GET', url, headers=headers, params=params)
        order = resp.json().get('order', {})
        customer = order.get('customer')
        if not customer or not customer.get('email'):
            return None
        return {
            'email': customer['email'],
            'first_name': customer.get('first_name', 'Customer'),
        }
    except Exception as e:
        logger.error("Failed to get customer for order %s on %s: %s", order_id, store_url, e)
        return None

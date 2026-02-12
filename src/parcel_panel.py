import time
import logging

from src import api_request_with_retry

logger = logging.getLogger(__name__)

BASE_URL = 'https://open.parcelpanel.com'
STUCK_STATUSES = {'PENDING', 'INFO_RECEIVED'}


def get_order_tracking(api_key, order_number):
    """Look up tracking info for an order via ParcelPanel API v2.

    Args:
        api_key: ParcelPanel API key for the store.
        order_number: Shopify order number (e.g. "#1030").

    Returns:
        dict with order data including 'shipments' list, or None on failure.
    """
    headers = {
        'x-parcelpanel-api-key': api_key,
        'Content-Type': 'application/json',
    }
    params = {'order_number': order_number}
    url = f"{BASE_URL}/api/v2/tracking/order"

    try:
        resp = api_request_with_retry('GET', url, headers=headers, params=params)
        data = resp.json()
        return data.get('order')
    except Exception as e:
        logger.error("ParcelPanel lookup failed for order %s: %s", order_number, e)
        return None


def get_stuck_shipments(tracking_data):
    """Extract stuck shipments from a ParcelPanel order response.

    Returns list of shipment dicts where status is PENDING or INFO_RECEIVED.
    """
    if not tracking_data or not tracking_data.get('shipments'):
        return []

    stuck = []
    for shipment in tracking_data['shipments']:
        status = (shipment.get('status') or '').upper()
        if status in STUCK_STATUSES:
            stuck.append(shipment)
    return stuck


def get_tracking_url(tracking_data):
    """Get the tracking page URL from ParcelPanel order data."""
    if not tracking_data:
        return ''
    return tracking_data.get('tracking_link', '')

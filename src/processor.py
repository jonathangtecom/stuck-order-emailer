import os
import time
import logging
from datetime import datetime, timezone

from jinja2.sandbox import SandboxedEnvironment

from src import database
from src import shopify_client
from src import parcel_panel
from src import email_sender

logger = logging.getLogger(__name__)

try:
    import sentry_sdk
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
TEMPLATES_PATH = os.environ.get('TEMPLATES_PATH', 'data/templates')


def process_all_stores(dry_run=False):
    """Process all enabled stores. Returns summary dict.

    If dry_run=True, runs the full pipeline (Shopify fetch, ParcelPanel check,
    template rendering) but skips sending emails and recording to the database.
    Returns detailed info about what would have been sent.
    """
    stores = database.get_enabled_stores()
    summary = {
        'processed': 0,
        'emails_sent': 0,
        'skipped': 0,
        'errors': 0,
        'dry_run': dry_run,
        'details': [],
    }

    mode = "DRY RUN" if dry_run else "LIVE"
    logger.info("[%s] Starting processing run for %d enabled stores", mode, len(stores))

    for store in stores:
        result = _process_store_with_retry(store, dry_run=dry_run)
        if 'error' in result:
            summary['errors'] += 1
            summary['details'].append({
                'store': store['name'],
                'error': result['error'],
            })
        else:
            summary['emails_sent'] += result['sent']
            summary['skipped'] += result['skipped']
            summary['processed'] += 1
            detail = {
                'store': store['name'],
                'sent': result['sent'],
                'skipped': result['skipped'],
            }
            if dry_run and result.get('would_send'):
                detail['would_send'] = result['would_send']
            summary['details'].append(detail)

    logger.info("[%s] Run complete: %s", mode, summary)
    return summary


STORE_RETRY_ATTEMPTS = int(os.environ.get('STORE_RETRY_ATTEMPTS', 3))
STORE_RETRY_BASE_DELAY = int(os.environ.get('STORE_RETRY_BASE_DELAY', 60))  # seconds


def _process_store_with_retry(store, dry_run=False):
    """Try processing a store with retries on transient failures.

    If the Shopify or ParcelPanel API is temporarily down, waits and retries
    the entire store (default: 3 attempts with 60s/120s/240s delays).
    One store failing NEVER blocks others.
    """
    last_error = None
    for attempt in range(STORE_RETRY_ATTEMPTS):
        try:
            return process_store(store, dry_run=dry_run)
        except Exception as e:
            last_error = e
            if attempt < STORE_RETRY_ATTEMPTS - 1:
                wait = STORE_RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Store %s failed (attempt %d/%d): %s — retrying in %ds",
                    store['name'], attempt + 1, STORE_RETRY_ATTEMPTS, e, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "Store %s failed after %d attempts: %s",
                    store['name'], STORE_RETRY_ATTEMPTS, e, exc_info=True,
                )
    return {'error': str(last_error)}


def process_store(store, dry_run=False):
    """Process a single store. Returns dict with sent/skipped counts."""
    store_id = store['id']
    store_name = store['name']
    days_threshold = store.get('days_threshold', 8)

    # Add Sentry context for this store
    if SENTRY_AVAILABLE:
        sentry_sdk.set_tag('store_id', store_id)
        sentry_sdk.set_tag('store_name', store_name)
        sentry_sdk.set_context('store', {
            'id': store_id,
            'name': store_name,
            'days_threshold': days_threshold,
        })

    logger.info("Processing store: %s (threshold: %d days)", store_name, days_threshold)

    # Load and validate the email template
    template_html = _load_template(store['email_template'])
    if template_html is None:
        raise ValueError(f"Template '{store['email_template']}' not found or unreadable")

    # Fetch recent orders (shipped + unshipped) from Shopify
    # Look back further than the threshold to catch orders that just crossed it
    days_back = max(days_threshold + 14, 30)
    orders = shopify_client.get_recent_orders(
        store['shopify_store_url'],
        store['shopify_admin_api_token'],
        days_back=days_back,
    )

    sent = 0
    skipped = 0
    would_send = []  # Only populated in dry_run mode

    for order in orders:
        try:
            result = _process_order(store, order, days_threshold, template_html, dry_run=dry_run)
            if isinstance(result, dict):
                # Dry-run returns detail dicts for would-send orders
                sent += 1
                would_send.append(result)
            elif result == 'sent':
                sent += 1
            elif result == 'skipped':
                skipped += 1
        except Exception as e:
            logger.error("Error processing order %s in store %s: %s",
                         order.get('name', '?'), store_name, e)
            continue  # One bad order never blocks others

    logger.info("Store %s: sent=%d, skipped=%d", store_name, sent, skipped)
    output = {'sent': sent, 'skipped': skipped}
    if dry_run:
        output['would_send'] = would_send
    return output


def _process_order(store, order, days_threshold, template_html, dry_run=False):
    """Process a single order. Returns 'sent', 'skipped', None, or a detail dict (dry_run)."""
    order_id = str(order['id'])
    order_number = order.get('name', '')
    store_id = store['id']

    # Add Sentry breadcrumb for order processing
    if SENTRY_AVAILABLE:
        sentry_sdk.add_breadcrumb(
            category='order',
            message=f'Processing order {order_number}',
            level='info',
            data={
                'order_id': order_id,
                'order_number': order_number,
                'store_id': store_id,
            }
        )

    # Skip cancelled orders
    if order.get('cancelled_at'):
        return None

    # Dedup check — skip if already emailed (fast DB check, no API cost)
    if database.is_email_sent(store_id, order_id):
        return 'skipped'

    # Age check
    order_created = order.get('created_at', '')
    order_date = _parse_date(order_created)
    if order_date is None:
        return None

    now = datetime.now(timezone.utc)
    days_waiting = (now - order_date).days
    if days_waiting < days_threshold:
        return None  # Not old enough yet

    # Extract customer info from the Shopify order data
    customer = order.get('customer') or {}
    customer_email = customer.get('email')
    first_name = (customer.get('first_name') or '').strip()
    last_name = (customer.get('last_name') or '').strip()
    customer_name = f'{first_name} {last_name}'.strip() or 'Customer'
    first_name = first_name or customer_name

    if not customer_email:
        logger.warning("No email for order %s in store %s, skipping",
                        order_number, store['name'])
        return 'skipped'

    # Determine if order has fulfillments (tracking) or is unfulfilled
    fulfillments = order.get('fulfillments') or []
    is_unfulfilled = len(fulfillments) == 0

    if is_unfulfilled:
        # Order hasn't shipped at all — no ParcelPanel check needed
        tracking_number = 'N/A'
        tracking_status = 'UNFULFILLED'
        tracking_url = ''
        logger.info("Order %s in store %s is unfulfilled after %d days",
                     order_number, store['name'], days_waiting)
    else:
        # Order has tracking — check ParcelPanel for stuck status
        tracking_data = parcel_panel.get_order_tracking(
            store['parcel_panel_api_key'],
            order_number,
        )

        # Rate limiting for ParcelPanel (120 req/min)
        time.sleep(0.5)

        stuck_shipments = parcel_panel.get_stuck_shipments(tracking_data)
        if not stuck_shipments:
            return None  # Tracking is moving — not stuck

        shipment = stuck_shipments[0]
        tracking_number = shipment.get('tracking_number', 'N/A')
        tracking_status = shipment.get('status', '')
        tracking_url = parcel_panel.get_tracking_url(tracking_data)

    # Render email template and subject with Jinja2
    template_vars = {
        'customer_name': customer_name,
        'first_name': first_name,
        'order_number': order_number,
        'tracking_number': tracking_number,
        'tracking_url': tracking_url,
        'store_name': store['name'],
        'order_date': order_date.strftime('%B %d, %Y'),
        'days_waiting': str(days_waiting),
    }

    try:
        rendered_subject = _render_template_string(store['email_subject'], template_vars)
        rendered_body = _render_template_string(template_html, template_vars)
    except Exception as e:
        logger.error("Template rendering failed for store %s, order %s: %s",
                      store['name'], order_number, e)
        return 'skipped'

    # ── Dry run: log what would happen, skip send + DB ──
    if dry_run:
        logger.info("[DRY RUN] Would send email for order %s to %s (store: %s, waiting: %d days)",
                     order_number, customer_email, store['name'], days_waiting)
        return {
            'order_number': order_number,
            'customer_email': customer_email,
            'customer_name': customer_name,
            'tracking_number': tracking_number,
            'tracking_status': tracking_status,
            'days_waiting': days_waiting,
            'subject': rendered_subject,
        }

    # ── Live: send email via SendGrid ──
    success = email_sender.send_email(
        to_email=customer_email,
        from_email=store['from_email'],
        from_name=store['from_name'],
        subject=rendered_subject,
        html_content=rendered_body,
        sendgrid_api_key=SENDGRID_API_KEY,
    )

    if success:
        database.record_sent_email({
            'store_id': store_id,
            'store_name': store['name'],
            'order_id': order_id,
            'order_number': order_number,
            'customer_email': customer_email,
            'tracking_number': tracking_number,
            'tracking_status': tracking_status,
            'days_waiting': days_waiting,
        })
        logger.info("Sent email for order %s to %s (store: %s, waiting: %d days)",
                     order_number, customer_email, store['name'], days_waiting)
        return 'sent'
    else:
        logger.error("Failed to send email for order %s to %s", order_number, customer_email)
        return 'skipped'


def _load_template(template_filename):
    """Load an email HTML template from the templates directory."""
    path = os.path.join(TEMPLATES_PATH, template_filename)
    real_path = os.path.realpath(path)
    real_templates = os.path.realpath(TEMPLATES_PATH)
    if not real_path.startswith(real_templates):
        logger.error("Template path traversal attempt: %s", template_filename)
        return None
    try:
        with open(real_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error("Template file not found: %s", path)
        return None
    except Exception as e:
        logger.error("Error reading template %s: %s", path, e)
        return None


def _render_template_string(template_str, variables):
    """Render a Jinja2 template string with the given variables in a sandbox."""
    env = SandboxedEnvironment()
    template = env.from_string(template_str)
    return template.render(**variables)


def _parse_date(date_str):
    """Parse an ISO 8601 date string into a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        # Shopify dates look like: 2024-01-15T10:30:00-05:00
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        logger.warning("Could not parse date: %s", date_str)
        return None

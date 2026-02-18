import os
import re
import csv
import hmac
import math
import secrets
import logging
import functools
from io import StringIO
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, Response,
)
from jinja2.sandbox import SandboxedEnvironment

from apscheduler.schedulers.background import BackgroundScheduler

from src import database
from src import processor

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.logging import LoggingIntegration

# ── Sentry Helper Functions ──────────────────────────────────

def _get_release_version():
    """Get release version from git commit or Docker image tag."""
    try:
        # Try to get git commit hash
        import subprocess
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            return f"stuck-order-emailer@{result.stdout.strip()}"
    except Exception:
        pass

    # Fallback to environment variable (set in Docker build)
    return os.environ.get('SENTRY_RELEASE', 'stuck-order-emailer@unknown')


def _sentry_before_send(event, hint):
    """Filter and enrich events before sending to Sentry.

    This is critical for:
    1. Removing sensitive data (API keys, passwords)
    2. Staying within free tier limits
    3. Adding useful context
    """
    # Filter out sensitive data from event
    if 'request' in event:
        # Remove sensitive headers
        if 'headers' in event['request']:
            sensitive_headers = [
                'X-Shopify-Access-Token',
                'x-parcelpanel-api-key',
                'Authorization',
                'Cookie',
            ]
            for header in sensitive_headers:
                if header in event['request']['headers']:
                    event['request']['headers'][header] = '[Filtered]'

        # Filter sensitive data from request body
        if 'data' in event['request']:
            sensitive_fields = [
                'parcel_panel_api_key',
                'shopify_admin_api_token',
                'password',
                'sendgrid_api_key',
            ]
            if isinstance(event['request']['data'], dict):
                for field in sensitive_fields:
                    if field in event['request']['data']:
                        event['request']['data'][field] = '[Filtered]'

    # Filter sensitive data from exception context
    if 'exception' in event and 'values' in event['exception']:
        for exc in event['exception']['values']:
            if 'stacktrace' in exc and 'frames' in exc['stacktrace']:
                for frame in exc['stacktrace']['frames']:
                    if 'vars' in frame:
                        sensitive_vars = [
                            'api_key', 'api_token', 'password',
                            'sendgrid_api_key', 'SENDGRID_API_KEY',
                            'ADMIN_PASSWORD', 'SECRET_KEY',
                        ]
                        for var in sensitive_vars:
                            if var in frame['vars']:
                                frame['vars'][var] = '[Filtered]'

    return event


# ── Sentry Configuration ─────────────────────────────────────

SENTRY_DSN = os.environ.get('SENTRY_DSN', '')
SENTRY_ENV = os.environ.get('SENTRY_ENVIRONMENT', 'development')
SENTRY_TRACES_SAMPLE_RATE = float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '0.0'))

if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=SENTRY_ENV,
        integrations=[
            FlaskIntegration(),
            LoggingIntegration(
                level=logging.INFO,        # Capture info and above as breadcrumbs
                event_level=logging.ERROR  # Send errors and above as events
            ),
        ],
        traces_sample_rate=SENTRY_TRACES_SAMPLE_RATE,
        send_default_pii=False,  # Don't send user IPs, cookies automatically
        before_send=_sentry_before_send,
        release=_get_release_version(),
    )

# ── Logging ──────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)
logging.getLogger('apscheduler').setLevel(logging.WARNING)

if SENTRY_DSN:
    logger.info("Sentry initialized: environment=%s", SENTRY_ENV)
else:
    logger.info("Sentry disabled (no SENTRY_DSN configured)")

# ── App Configuration ────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')
TEMPLATES_PATH = os.environ.get('TEMPLATES_PATH', 'data/templates')
DATABASE_PATH = os.environ.get('DATABASE_PATH', 'data/app.db')

# Set database path for the database module
database.DATABASE_PATH = DATABASE_PATH

# Ensure data directories exist
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(TEMPLATES_PATH, exist_ok=True)

# Initialize database on startup
database.init_db()

logger.info("App starting — DB: %s, Templates: %s", DATABASE_PATH, TEMPLATES_PATH)

# ── Scheduler (per-store) ─────────────────────────────────────

SCHEDULE_HOUR = int(os.environ.get('SCHEDULE_HOUR', '9'))
SCHEDULE_MINUTE = int(os.environ.get('SCHEDULE_MINUTE', '0'))

scheduler = BackgroundScheduler()


def _scheduled_process_single_store(store_id):
    """Wrapper for per-store scheduled job with Sentry error tracking."""
    try:
        return processor.process_single_store_by_id(store_id)
    except Exception as e:
        if SENTRY_DSN:
            sentry_sdk.capture_exception(e)
        logger.error("Scheduled processing failed for store %s: %s", store_id, e, exc_info=True)
        raise


def _store_job_id(store_id):
    return f'store_{store_id}'


def _register_store_job(store):
    """Add or replace a cron job for an enabled store."""
    if not store or not store.get('enabled'):
        return
    job_id = _store_job_id(store['id'])
    hour = store.get('send_hour', SCHEDULE_HOUR)
    minute = store.get('send_minute', SCHEDULE_MINUTE)

    # Remove existing job first (if any) to update schedule
    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass

    scheduler.add_job(
        _scheduled_process_single_store,
        trigger='cron',
        hour=hour,
        minute=minute,
        args=[store['id']],
        id=job_id,
        misfire_grace_time=3600,
    )
    logger.info("Scheduled store '%s' at %02d:%02d UTC", store['name'], hour, minute)


def _unregister_store_job(store_id):
    """Remove a store's scheduled job if it exists."""
    try:
        scheduler.remove_job(_store_job_id(store_id))
        logger.info("Unregistered scheduled job for store %s", store_id)
    except Exception:
        pass  # Job didn't exist


def _sync_all_store_jobs():
    """Register jobs for all enabled stores. Called on startup."""
    stores = database.get_enabled_stores()
    for store in stores:
        _register_store_job(store)
    logger.info("Scheduler synced — %d store job(s) registered", len(stores))


# Avoid starting scheduler twice in Flask debug mode (reloader spawns a child process)
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
    scheduler.start()
    _sync_all_store_jobs()


# ── Security Headers ──────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://esm.sh 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "connect-src 'self' https://esm.sh; "
        "img-src 'self' data: https:; "
        "frame-src 'self'"
    )
    return response


# ── Auth ─────────────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.before_request
def add_sentry_context():
    """Add useful context to Sentry for each request."""
    if not SENTRY_DSN:
        return

    # Set user context (authenticated status only, no PII)
    sentry_sdk.set_user({
        'authenticated': session.get('authenticated', False),
    })

    # Add request metadata as tags for filtering in Sentry
    sentry_sdk.set_tag('route', request.endpoint)
    sentry_sdk.set_tag('method', request.method)


# ── CSRF Protection ──────────────────────────────────────────

def _generate_csrf_token():
    """Generate a CSRF token for the current session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = _generate_csrf_token


@app.before_request
def csrf_protect():
    """Validate CSRF token on state-changing requests."""
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return

    # /api/run: skip CSRF for non-browser auth (localhost or Bearer token)
    if request.endpoint == 'api_run':
        remote = request.remote_addr
        bearer = request.headers.get('Authorization', '').replace('Bearer ', '')
        is_local = remote in ALLOWED_RUN_IPS
        is_token = RUN_TOKEN and hmac.compare_digest(bearer, RUN_TOKEN or '')
        if is_local or is_token:
            return

    token = (
        request.form.get('csrf_token')
        or request.headers.get('X-CSRF-Token')
    )

    expected = session.get('csrf_token')
    if not token or not expected or not hmac.compare_digest(token, expected):
        if request.is_json:
            return jsonify({'error': 'CSRF token missing or invalid'}), 403
        flash('Session expired. Please try again.', 'error')
        return redirect(request.referrer or url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if hmac.compare_digest(request.form.get('password', ''), ADMIN_PASSWORD):
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        flash('Invalid password.', 'error')
    return render_template('ui/login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Dashboard ────────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    stores = database.get_all_stores()
    stats = database.get_email_stats()
    enabled = sum(1 for s in stores if s['enabled'])

    return render_template('ui/dashboard.html',
                           active_page='dashboard',
                           stores=stores,
                           stats=stats,
                           total_stores=len(stores),
                           enabled_stores=enabled)


# ── Dry Run ──────────────────────────────────────────────────

@app.route('/dry-run')
@login_required
def dry_run():
    stores = database.get_enabled_stores()
    return render_template('ui/dry_run.html',
                           active_page='dry_run', stores=stores)


# ── Store CRUD ───────────────────────────────────────────────

@app.route('/stores')
@login_required
def store_list():
    stores = database.get_all_stores()
    return render_template('ui/stores.html',
                           active_page='stores',
                           stores=stores)


@app.route('/stores/new')
@login_required
def store_new():
    templates = _list_template_files()
    return render_template('ui/store_form.html',
                           active_page='stores',
                           store=None,
                           templates=templates)


@app.route('/stores', methods=['POST'])
@login_required
def store_create():
    data = _extract_store_form(request.form)

    # Validate required fields
    required = ['name', 'parcel_panel_api_key', 'shopify_store_url',
                'shopify_admin_api_token', 'from_email', 'from_name',
                'email_subject', 'email_template']
    missing = [f for f in required if not data.get(f)]
    if missing:
        flash(f"Missing required fields: {', '.join(missing)}", 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store=data,
                               templates=templates)

    if not _is_valid_email(data['from_email']):
        flash('Invalid from_email format.', 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store=data,
                               templates=templates)

    template_error = _validate_templates(data['email_subject'], data['email_template'])
    if template_error:
        flash(template_error, 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store=data,
                               templates=templates)

    try:
        store_id = database.create_store(data)
        _register_store_job(database.get_store(store_id))
        flash(f'Store "{data["name"]}" created (ID: {store_id}).', 'success')
    except Exception as e:
        logger.error("Failed to create store: %s", e)
        flash(f'Error creating store: {e}', 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store=data,
                               templates=templates)

    return redirect(url_for('store_list'))


@app.route('/stores/<store_id>/edit')
@login_required
def store_edit(store_id):
    store = database.get_store(store_id)
    if not store:
        flash('Store not found.', 'error')
        return redirect(url_for('store_list'))

    templates = _list_template_files()
    return render_template('ui/store_form.html',
                           active_page='stores',
                           store=store,
                           templates=templates)


@app.route('/stores/<store_id>', methods=['POST'])
@login_required
def store_update(store_id):
    store = database.get_store(store_id)
    if not store:
        flash('Store not found.', 'error')
        return redirect(url_for('store_list'))

    data = _extract_store_form(request.form)

    # For password fields, keep existing value if blank
    if not data.get('parcel_panel_api_key'):
        data['parcel_panel_api_key'] = store['parcel_panel_api_key']
    if not data.get('shopify_admin_api_token'):
        data['shopify_admin_api_token'] = store['shopify_admin_api_token']

    if data.get('from_email') and not _is_valid_email(data['from_email']):
        flash('Invalid from_email format.', 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store={**store, **data},
                               templates=templates)

    template_error = _validate_templates(
        data.get('email_subject') or store['email_subject'],
        data.get('email_template') or store['email_template'],
    )
    if template_error:
        flash(template_error, 'error')
        templates = _list_template_files()
        return render_template('ui/store_form.html',
                               active_page='stores',
                               store={**store, **data},
                               templates=templates)

    try:
        database.update_store(store_id, data)
        updated_store = database.get_store(store_id)
        if updated_store and updated_store['enabled']:
            _register_store_job(updated_store)
        else:
            _unregister_store_job(store_id)
        flash('Store updated.', 'success')
    except Exception as e:
        logger.error("Failed to update store %s: %s", store_id, e)
        flash(f'Error updating store: {e}', 'error')

    return redirect(url_for('store_list'))


@app.route('/stores/<store_id>/toggle', methods=['POST'])
@login_required
def store_toggle(store_id):
    new_state = database.toggle_store(store_id)
    if new_state is None:
        return jsonify({'error': 'Store not found'}), 404
    if new_state:
        store = database.get_store(store_id)
        _register_store_job(store)
    else:
        _unregister_store_job(store_id)
    return jsonify({'enabled': new_state})


@app.route('/stores/<store_id>/delete', methods=['POST'])
@login_required
def store_delete(store_id):
    store = database.get_store(store_id)
    if store:
        _unregister_store_job(store_id)
        database.delete_store_cascade(store_id)
        flash(f'Store "{store["name"]}" deleted.', 'success')
    else:
        flash('Store not found.', 'error')
    return redirect(url_for('store_list'))


# ── Template Editor ──────────────────────────────────────────

@app.route('/templates')
@login_required
def template_editor():
    return render_template('ui/template_editor.html',
                           active_page='templates')


@app.route('/api/templates')
@login_required
def api_template_list():
    templates = _list_template_files()
    logger.info("Template list requested: found %d files: %s", len(templates), templates)
    return jsonify({'templates': templates})


@app.route('/api/templates/<filename>')
@login_required
def api_template_get(filename):
    if not _is_safe_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400

    filepath = _safe_template_path(filename)
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.info("Loaded template %s: %d bytes, first 100 chars: %s",
                   filename, len(content), content[:100] if content else '(empty)')
        return jsonify({'filename': filename, 'content': content})
    except FileNotFoundError:
        logger.error("Template not found: %s (resolved path: %s)", filename, filepath)
        return jsonify({'error': 'File not found'}), 404


@app.route('/api/templates/<filename>', methods=['POST'])
@login_required
def api_template_save(filename):
    if not _is_safe_filename(filename):
        return jsonify({'error': 'Invalid filename. Use only letters, numbers, hyphens, underscores, and dots. Must end in .html'}), 400

    filepath = _safe_template_path(filename)
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400

    data = request.get_json()
    if data is None:
        return jsonify({'error': 'JSON body required'}), 400

    content = data.get('content', '')

    # Validate Jinja2 syntax before saving (prevents silently breaking stores)
    try:
        env = SandboxedEnvironment()
        env.from_string(content).render(**_TEMPLATE_DUMMY_VARS)
    except Exception as e:
        return jsonify({'error': f'Template syntax error: {e}'}), 400

    try:
        # Write the file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        # Verify the file was written correctly
        with open(filepath, 'r', encoding='utf-8') as f:
            written_content = f.read()

        if written_content != content:
            logger.error("File verification failed for %s: content mismatch", filename)
            return jsonify({'error': 'File verification failed: content mismatch'}), 500

        logger.info("Successfully saved and verified template %s (%d bytes)", filename, len(content))
        return jsonify({'ok': True, 'bytes_written': len(content)})
    except Exception as e:
        logger.error("Failed to save template %s: %s", filename, e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates/<filename>', methods=['DELETE'])
@login_required
def api_template_delete(filename):
    if not _is_safe_filename(filename):
        return jsonify({'error': 'Invalid filename'}), 400

    filepath = _safe_template_path(filename)
    if filepath is None:
        return jsonify({'error': 'Invalid path'}), 400

    try:
        os.remove(filepath)
        return jsonify({'ok': True})
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404


@app.route('/api/templates/preview', methods=['POST'])
@login_required
def api_template_preview():
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({'error': 'content field required'}), 400

    sample_data = {
        'customer_name': 'John Doe',
        'first_name': 'John',
        'order_number': '#1042',
        'tracking_number': 'YT2312345678',
        'tracking_url': 'https://parcelpanel.com/track/YT2312345678',
        'store_name': 'Example Store',
        'order_date': 'January 28, 2026',
        'days_waiting': '10',
    }

    try:
        env = SandboxedEnvironment()
        template = env.from_string(data['content'])
        rendered = template.render(**sample_data)
        return rendered, 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({'error': f'Template error: {e}'}), 400


@app.route('/api/templates/send-test', methods=['POST'])
@login_required
def api_template_send_test():
    """Send a test email with the template using sample data."""
    from src.email_sender import send_email

    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    # Validate required fields
    required_fields = ['content', 'to_email', 'from_email', 'from_name', 'subject']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400

    # Validate email format
    if not _is_valid_email(data['to_email']) or not _is_valid_email(data['from_email']):
        return jsonify({'error': 'Invalid email format'}), 400

    # Get SendGrid API key from environment
    sendgrid_api_key = os.environ.get('SENDGRID_API_KEY', '')
    if not sendgrid_api_key or sendgrid_api_key == 'SG.your-key-here':
        return jsonify({'error': 'SENDGRID_API_KEY not configured in environment variables'}), 400

    # Sample data for template rendering
    sample_data = {
        'customer_name': 'John Doe',
        'first_name': 'John',
        'order_number': '#1042',
        'tracking_number': 'YT2312345678',
        'tracking_url': 'https://parcelpanel.com/track/YT2312345678',
        'store_name': 'Example Store',
        'order_date': 'January 28, 2026',
        'days_waiting': '10',
    }

    try:
        # Render template
        env = SandboxedEnvironment()
        template = env.from_string(data['content'])
        html_content = template.render(**sample_data)

        # Render subject line (also supports Jinja2 variables)
        subject_template = env.from_string(data['subject'])
        subject = subject_template.render(**sample_data)

        # Send email
        success = send_email(
            to_email=data['to_email'],
            from_email=data['from_email'],
            from_name=data['from_name'],
            subject=subject,
            html_content=html_content,
            sendgrid_api_key=sendgrid_api_key,
        )

        if success:
            logger.info("Test email sent to %s", data['to_email'])
            return jsonify({'ok': True, 'message': f'Test email sent to {data["to_email"]}'})
        else:
            return jsonify({'error': 'Failed to send email. Check server logs for details.'}), 500

    except Exception as e:
        logger.error("Test email failed: %s", e)
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/api/system/diagnostics')
@login_required
def api_diagnostics():
    """Diagnostic endpoint to verify file paths and volume mounts."""
    import pwd

    diagnostics = {
        'templates_path': TEMPLATES_PATH,
        'database_path': DATABASE_PATH,
        'templates_path_absolute': os.path.abspath(TEMPLATES_PATH),
        'database_path_absolute': os.path.abspath(DATABASE_PATH),
        'templates_dir_exists': os.path.exists(TEMPLATES_PATH),
        'templates_dir_writable': os.access(TEMPLATES_PATH, os.W_OK),
        'database_exists': os.path.exists(DATABASE_PATH),
        'current_user': pwd.getpwuid(os.getuid()).pw_name,
        'working_directory': os.getcwd(),
    }

    # Check actual files in templates directory
    if os.path.exists(TEMPLATES_PATH):
        try:
            files = os.listdir(TEMPLATES_PATH)
            diagnostics['template_files'] = files
            diagnostics['template_files_count'] = len(files)
        except Exception as e:
            diagnostics['template_files_error'] = str(e)

    return jsonify(diagnostics)


# ── Logs ─────────────────────────────────────────────────────

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    store_id = request.args.get('store', '').strip() or None
    date_from = request.args.get('date_from', '').strip() or None
    date_to = request.args.get('date_to', '').strip() or None

    per_page = 50
    emails, total = database.get_sent_emails(
        store_id=store_id,
        page=page,
        per_page=per_page,
        date_from=date_from,
        date_to=date_to,
    )
    total_pages = max(1, math.ceil(total / per_page))

    stores = database.get_all_stores()

    return render_template('ui/logs.html',
                           active_page='logs',
                           emails=emails,
                           stores=stores,
                           page=page,
                           total_pages=total_pages,
                           filter_store=store_id or '',
                           filter_date_from=date_from or '',
                           filter_date_to=date_to or '')


@app.route('/logs/export')
@login_required
def logs_export():
    store_id = request.args.get('store', '').strip() or None
    emails = database.get_all_sent_emails_for_export(store_id=store_id)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Store', 'Order Number', 'Customer Email', 'Tracking Number',
                     'Tracking Status', 'Days Waiting', 'Sent At'])
    for e in emails:
        writer.writerow([
            _csv_safe(e['store_name']), _csv_safe(e['order_number']),
            _csv_safe(e['customer_email']),
            _csv_safe(e.get('tracking_number', '')),
            _csv_safe(e.get('tracking_status', '')),
            e.get('days_waiting', ''), e['sent_at'],
        ])

    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=sent-emails-{today}.csv'},
    )


# ── Cron / API Run ───────────────────────────────────────────

ALLOWED_RUN_IPS = {'127.0.0.1', '::1'}
# Docker bridge network IPs
for i in range(16, 32):
    ALLOWED_RUN_IPS.add(f'172.{i}.0.1')

RUN_TOKEN = os.environ.get('RUN_TOKEN', '')


@app.route('/api/run', methods=['POST'])
def api_run():
    # Auth: localhost/Docker IP, bearer token, or logged-in session
    remote = request.remote_addr
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    is_local = remote in ALLOWED_RUN_IPS
    is_token_valid = RUN_TOKEN and hmac.compare_digest(token, RUN_TOKEN or '')
    is_session = session.get('authenticated')

    if not is_local and not is_token_valid and not is_session:
        logger.warning("Unauthorized /api/run attempt from %s", remote)
        return jsonify({'error': 'Unauthorized'}), 403

    dry_run = request.args.get('dry_run', '0') == '1'
    store_id = request.args.get('store_id', '') or None
    mode = "DRY RUN" if dry_run else "LIVE"
    logger.info("[%s] Processing run triggered from %s", mode, remote)
    try:
        summary = processor.process_all_stores(dry_run=dry_run, store_id=store_id)
        return jsonify(summary)
    except Exception as e:
        logger.error("Processing run failed: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


# ── Helpers ──────────────────────────────────────────────────

def _extract_store_form(form):
    """Extract store data from a form submission."""
    # Parse "HH:MM" time field into send_hour/send_minute
    send_time = form.get('send_time', '09:00').strip()
    try:
        parts = send_time.split(':')
        send_hour = max(0, min(23, int(parts[0])))
        send_minute = max(0, min(59, int(parts[1])))
    except (ValueError, IndexError):
        send_hour, send_minute = 9, 0

    return {
        'id': form.get('id', '').strip(),
        'name': form.get('name', '').strip(),
        'parcel_panel_api_key': form.get('parcel_panel_api_key', '').strip(),
        'shopify_store_url': form.get('shopify_store_url', '').strip(),
        'shopify_admin_api_token': form.get('shopify_admin_api_token', '').strip(),
        'from_email': form.get('from_email', '').strip(),
        'from_name': form.get('from_name', '').strip(),
        'email_subject': form.get('email_subject', '').strip(),
        'email_template': form.get('email_template', '').strip(),
        'days_threshold': form.get('days_threshold', '8').strip(),
        'send_hour': send_hour,
        'send_minute': send_minute,
    }


def _is_valid_email(email):
    """
    Validate email address format per RFC 5321.

    Requirements:
    - Max length: 254 characters
    - Format: local-part@domain
    - Local part: alphanumeric, dots, hyphens, underscores, plus signs
    - Domain: alphanumeric, dots, hyphens, at least one dot, valid TLD
    """
    if not email or len(email) > 254:
        return False

    # Split at @ exactly once
    if email.count('@') != 1:
        return False

    local, domain = email.split('@')

    # Validate local part
    if not local or len(local) > 64:  # RFC 5321 limit
        return False
    if '..' in local or local.startswith('.') or local.endswith('.'):
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*$', local):
        return False

    # Validate domain
    if not domain or len(domain) > 253:  # RFC 1035 limit
        return False
    if '..' in domain or domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False
    if '.' not in domain:
        return False

    # Validate domain labels
    labels = domain.split('.')
    for label in labels:
        if not label or len(label) > 63:  # RFC 1035 limit
            return False
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', label):
            return False

    # TLD must be 2+ chars, alphabetic
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    return True


_TEMPLATE_DUMMY_VARS = {
    'customer_name': 'Test Customer', 'first_name': 'Test',
    'order_number': '#0000', 'tracking_number': 'N/A', 'tracking_url': '',
    'store_name': 'Test Store', 'order_date': 'January 01, 2025',
    'days_waiting': '8',
}


def _validate_templates(subject, template_filename):
    """Validate email subject and template for Jinja2 syntax errors.

    Returns None on success, or an error message string on failure.
    """
    env = SandboxedEnvironment()
    try:
        env.from_string(subject).render(**_TEMPLATE_DUMMY_VARS)
    except Exception as e:
        return f'Email subject template error: {e}'

    # Load template from app's TEMPLATES_PATH (not processor's which tests may mutate)
    path = _safe_template_path(template_filename)
    if not path:
        return f'Template file "{template_filename}" not found.'
    try:
        with open(path, 'r', encoding='utf-8') as f:
            template_html = f.read()
    except FileNotFoundError:
        return f'Template file "{template_filename}" not found.'

    try:
        env.from_string(template_html).render(**_TEMPLATE_DUMMY_VARS)
    except Exception as e:
        return f'Email template error: {e}'

    return None


def _csv_safe(value):
    """Sanitize a value for CSV export to prevent formula injection in spreadsheets."""
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def _is_safe_filename(filename):
    """Check if a filename is safe: only alphanumeric, hyphens, underscores, dots, ending in .html."""
    return bool(re.match(r'^[a-zA-Z0-9._-]+\.html$', filename))


def _safe_template_path(filename):
    """Resolve a template filename to a safe absolute path inside TEMPLATES_PATH."""
    path = os.path.join(TEMPLATES_PATH, filename)
    real_path = os.path.realpath(path)
    real_templates = os.path.realpath(TEMPLATES_PATH)
    if not real_path.startswith(real_templates + os.sep):
        return None
    return real_path


def _list_template_files():
    """List all .html files in the templates directory."""
    try:
        files = sorted(
            f for f in os.listdir(TEMPLATES_PATH)
            if f.endswith('.html') and _is_safe_filename(f)
        )
        return files
    except FileNotFoundError:
        return []


# ── Main ─────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)

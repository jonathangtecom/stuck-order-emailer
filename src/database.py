import os
import re
import sqlite3
import uuid
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

DATABASE_PATH = os.environ.get('DATABASE_PATH', 'data/app.db')


def _get_db_path():
    return DATABASE_PATH


@contextmanager
def get_connection():
    """Get a SQLite connection with WAL mode and Row factory."""
    conn = sqlite3.connect(_get_db_path(), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables and indexes if they don't exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS stores (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                parcel_panel_api_key TEXT NOT NULL,
                shopify_store_url TEXT NOT NULL,
                shopify_admin_api_token TEXT NOT NULL,
                from_email TEXT NOT NULL,
                from_name TEXT NOT NULL,
                email_subject TEXT NOT NULL,
                email_template TEXT NOT NULL,
                days_threshold INTEGER DEFAULT 8,
                send_hour INTEGER DEFAULT 9,
                send_minute INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sent_emails (
                id TEXT PRIMARY KEY,
                store_id TEXT NOT NULL,
                store_name TEXT NOT NULL,
                order_id TEXT NOT NULL,
                order_number TEXT NOT NULL,
                customer_email TEXT NOT NULL,
                tracking_number TEXT,
                tracking_status TEXT,
                days_waiting INTEGER,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (store_id) REFERENCES stores(id)
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_sent_emails_dedup ON sent_emails(store_id, order_id);
            CREATE INDEX IF NOT EXISTS idx_sent_emails_store ON sent_emails(store_id);
            CREATE INDEX IF NOT EXISTS idx_sent_emails_sent_at ON sent_emails(sent_at);
        """)

        # Migrations for existing databases
        for col, default in [('send_hour', 9), ('send_minute', 0)]:
            try:
                conn.execute(f"ALTER TABLE stores ADD COLUMN {col} INTEGER DEFAULT {default}")
            except sqlite3.OperationalError:
                pass  # Column already exists

    logger.info("Database initialized at %s", _get_db_path())


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def _slugify(name):
    slug = name.lower().strip().replace(' ', '-')
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    slug = re.sub(r'-+', '-', slug).strip('-')
    slug = slug[:60]  # Limit slug length
    return slug or 'store'


# ── Store CRUD ──────────────────────────────────────────────

def get_all_stores():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM stores ORDER BY name").fetchall()
        return [_row_to_dict(r) for r in rows]


def get_enabled_stores():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM stores WHERE enabled=1 ORDER BY name").fetchall()
        return [_row_to_dict(r) for r in rows]


def get_store(store_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        return _row_to_dict(row)


def create_store(data):
    store_id = data.get('id') or _slugify(data['name'])
    # Ensure uniqueness
    existing = get_store(store_id)
    if existing:
        store_id = f"{store_id}-{uuid.uuid4().hex[:6]}"

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO stores (id, name, enabled, parcel_panel_api_key, shopify_store_url,
                shopify_admin_api_token, from_email, from_name, email_subject,
                email_template, days_threshold, send_hour, send_minute)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            store_id,
            data['name'].strip(),
            1,
            data['parcel_panel_api_key'].strip(),
            data['shopify_store_url'].strip().rstrip('/'),
            data['shopify_admin_api_token'].strip(),
            data['from_email'].strip(),
            data['from_name'].strip(),
            data['email_subject'].strip(),
            data['email_template'].strip(),
            int(data.get('days_threshold', 8)),
            int(data.get('send_hour', 9)),
            int(data.get('send_minute', 0)),
        ))
    return store_id


def update_store(store_id, data):
    fields = []
    values = []
    updatable = [
        'name', 'parcel_panel_api_key', 'shopify_store_url',
        'shopify_admin_api_token', 'from_email', 'from_name',
        'email_subject', 'email_template', 'days_threshold',
        'send_hour', 'send_minute',
    ]
    for field in updatable:
        if field in data and data[field] is not None and data[field] != '':
            val = data[field].strip() if isinstance(data[field], str) else data[field]
            if field == 'shopify_store_url' and isinstance(val, str):
                val = val.rstrip('/')
            if field in ('days_threshold', 'send_hour', 'send_minute'):
                val = int(val)
            fields.append(f"{field}=?")
            values.append(val)

    if not fields:
        return

    fields.append("updated_at=?")
    values.append(datetime.now(timezone.utc).isoformat())
    values.append(store_id)

    with get_connection() as conn:
        conn.execute(
            f"UPDATE stores SET {', '.join(fields)} WHERE id=?",
            values,
        )


def delete_store(store_id):
    with get_connection() as conn:
        conn.execute("DELETE FROM stores WHERE id=?", (store_id,))


def delete_store_cascade(store_id):
    """Delete a store and all its associated sent_emails."""
    with get_connection() as conn:
        conn.execute("DELETE FROM sent_emails WHERE store_id=?", (store_id,))
        conn.execute("DELETE FROM stores WHERE id=?", (store_id,))


def toggle_store(store_id):
    with get_connection() as conn:
        row = conn.execute("SELECT enabled FROM stores WHERE id=?", (store_id,)).fetchone()
        if not row:
            return None
        new_state = 0 if row['enabled'] else 1
        conn.execute(
            "UPDATE stores SET enabled=?, updated_at=? WHERE id=?",
            (new_state, datetime.now(timezone.utc).isoformat(), store_id),
        )
        return bool(new_state)


# ── Sent Emails ─────────────────────────────────────────────

def is_email_sent(store_id, order_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM sent_emails WHERE store_id=? AND order_id=?",
            (store_id, str(order_id)),
        ).fetchone()
        return row is not None


def record_sent_email(data):
    email_id = data.get('id', uuid.uuid4().hex)
    with get_connection() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO sent_emails
                (id, store_id, store_name, order_id, order_number,
                 customer_email, tracking_number, tracking_status, days_waiting)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            email_id,
            data['store_id'],
            data['store_name'],
            str(data['order_id']),
            data['order_number'],
            data['customer_email'],
            data.get('tracking_number'),
            data.get('tracking_status'),
            data.get('days_waiting'),
        ))


def get_sent_emails(store_id=None, page=1, per_page=50, date_from=None, date_to=None):
    conditions = []
    params = []

    if store_id:
        conditions.append("store_id=?")
        params.append(store_id)
    if date_from:
        conditions.append("sent_at >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("sent_at <= ?")
        params.append(date_to + " 23:59:59")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * per_page

    with get_connection() as conn:
        total_row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM sent_emails {where}", params
        ).fetchone()
        total = total_row['cnt']

        rows = conn.execute(
            f"SELECT * FROM sent_emails {where} ORDER BY sent_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

        return [_row_to_dict(r) for r in rows], total


def get_email_stats():
    now = datetime.now(timezone.utc)
    today_start = now.strftime('%Y-%m-%d 00:00:00')
    week_start = (now - timedelta(days=7)).strftime('%Y-%m-%d 00:00:00')

    with get_connection() as conn:
        today_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sent_emails WHERE sent_at >= ?",
            (today_start,),
        ).fetchone()['cnt']

        week_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sent_emails WHERE sent_at >= ?",
            (week_start,),
        ).fetchone()['cnt']

        total_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sent_emails"
        ).fetchone()['cnt']

    return {
        'today_count': today_count,
        'week_count': week_count,
        'total_count': total_count,
    }


def get_all_sent_emails_for_export(store_id=None):
    conditions = []
    params = []
    if store_id:
        conditions.append("store_id=?")
        params.append(store_id)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM sent_emails {where} ORDER BY sent_at DESC", params
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

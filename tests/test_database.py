"""Unit tests for src/database.py"""
import os
import tempfile
import sqlite3
import pytest

# Set DB path before importing
_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')

from src import database


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Reset database for each test."""
    db_path = str(tmp_path / 'test.db')
    database.DATABASE_PATH = db_path
    database.init_db()
    yield db_path


def _make_store(**overrides):
    data = {
        'name': 'Test Store',
        'parcel_panel_api_key': 'pp-key',
        'shopify_store_url': 'test.myshopify.com',
        'shopify_admin_api_token': 'shpat_test',
        'from_email': 'test@example.com',
        'from_name': 'Test Team',
        'email_subject': 'Subject',
        'email_template': 'example.html',
        'days_threshold': 8,
    }
    data.update(overrides)
    return data


class TestInitDb:
    def test_wal_mode_enabled(self, fresh_db):
        conn = sqlite3.connect(fresh_db)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == 'wal'

    def test_tables_created(self, fresh_db):
        conn = sqlite3.connect(fresh_db)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert 'stores' in tables
        assert 'sent_emails' in tables

    def test_indexes_created(self, fresh_db):
        conn = sqlite3.connect(fresh_db)
        indexes = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()]
        conn.close()
        assert 'idx_sent_emails_dedup' in indexes
        assert 'idx_sent_emails_store' in indexes
        assert 'idx_sent_emails_sent_at' in indexes

    def test_idempotent(self, fresh_db):
        # Calling init_db twice shouldn't crash
        database.init_db()
        database.init_db()


class TestStoreCRUD:
    def test_create_and_get(self):
        store_id = database.create_store(_make_store())
        store = database.get_store(store_id)
        assert store is not None
        assert store['name'] == 'Test Store'
        assert store['enabled'] == 1

    def test_create_generates_slug(self):
        store_id = database.create_store(_make_store(name='My Cool Store'))
        assert store_id == 'my-cool-store'

    def test_create_custom_id(self):
        store_id = database.create_store(_make_store(id='custom-id'))
        assert store_id == 'custom-id'

    def test_create_duplicate_slug_gets_suffix(self):
        id1 = database.create_store(_make_store(name='Dup Store'))
        id2 = database.create_store(_make_store(name='Dup Store'))
        assert id1 == 'dup-store'
        assert id2.startswith('dup-store-')
        assert id1 != id2

    def test_slug_truncates_long_names(self):
        store_id = database.create_store(_make_store(name='A' * 200))
        assert len(store_id) <= 60

    def test_slug_special_chars(self):
        store_id = database.create_store(_make_store(name='Store (CN) & Stuff!'))
        assert store_id == 'store-cn-stuff'

    def test_slug_empty_name_fallback(self):
        store_id = database.create_store(_make_store(name='!!!'))
        assert store_id == 'store'

    def test_get_all_stores(self):
        database.create_store(_make_store(name='Store A'))
        database.create_store(_make_store(name='Store B'))
        stores = database.get_all_stores()
        assert len(stores) == 2

    def test_get_enabled_stores(self):
        id1 = database.create_store(_make_store(name='Enabled'))
        id2 = database.create_store(_make_store(name='Disabled'))
        database.toggle_store(id2)
        enabled = database.get_enabled_stores()
        assert len(enabled) == 1
        assert enabled[0]['name'] == 'Enabled'

    def test_update_store(self):
        store_id = database.create_store(_make_store())
        database.update_store(store_id, {'from_email': 'new@test.com'})
        store = database.get_store(store_id)
        assert store['from_email'] == 'new@test.com'

    def test_update_preserves_unmentioned_fields(self):
        store_id = database.create_store(_make_store())
        database.update_store(store_id, {'from_email': 'new@test.com'})
        store = database.get_store(store_id)
        assert store['name'] == 'Test Store'  # unchanged
        assert store['parcel_panel_api_key'] == 'pp-key'  # unchanged

    def test_delete_store(self):
        store_id = database.create_store(_make_store())
        database.delete_store(store_id)
        assert database.get_store(store_id) is None

    def test_toggle_store(self):
        store_id = database.create_store(_make_store())
        result = database.toggle_store(store_id)
        assert result is False
        store = database.get_store(store_id)
        assert store['enabled'] == 0

        result = database.toggle_store(store_id)
        assert result is True

    def test_toggle_nonexistent(self):
        assert database.toggle_store('nope') is None

    def test_get_nonexistent_store(self):
        assert database.get_store('nope') is None

    def test_store_url_strips_trailing_slash(self):
        store_id = database.create_store(
            _make_store(shopify_store_url='test.myshopify.com/')
        )
        store = database.get_store(store_id)
        assert store['shopify_store_url'] == 'test.myshopify.com'

    def test_create_store_with_send_time(self):
        store_id = database.create_store(
            _make_store(send_hour=14, send_minute=30)
        )
        store = database.get_store(store_id)
        assert store['send_hour'] == 14
        assert store['send_minute'] == 30

    def test_create_store_default_send_time(self):
        store_id = database.create_store(_make_store())
        store = database.get_store(store_id)
        assert store['send_hour'] == 9
        assert store['send_minute'] == 0

    def test_create_store_midnight_send_time(self):
        """send_hour=0 and send_minute=0 must not be treated as falsy."""
        store_id = database.create_store(
            _make_store(send_hour=0, send_minute=0)
        )
        store = database.get_store(store_id)
        assert store['send_hour'] == 0
        assert store['send_minute'] == 0

    def test_update_store_send_time(self):
        store_id = database.create_store(_make_store())
        database.update_store(store_id, {'send_hour': 15, 'send_minute': 45})
        store = database.get_store(store_id)
        assert store['send_hour'] == 15
        assert store['send_minute'] == 45

    def test_update_store_send_time_to_zero(self):
        """Updating send_hour to 0 must work (midnight UTC)."""
        store_id = database.create_store(_make_store(send_hour=12, send_minute=30))
        database.update_store(store_id, {'send_hour': 0, 'send_minute': 0})
        store = database.get_store(store_id)
        assert store['send_hour'] == 0
        assert store['send_minute'] == 0


class TestSentEmails:
    def _create_store_for_fk(self):
        return database.create_store(_make_store())

    def test_record_and_check(self):
        store_id = self._create_store_for_fk()
        database.record_sent_email({
            'store_id': store_id,
            'store_name': 'Test',
            'order_id': '1001',
            'order_number': '#1001',
            'customer_email': 'c@test.com',
        })
        assert database.is_email_sent(store_id, '1001') is True
        assert database.is_email_sent(store_id, '9999') is False

    def test_dedup_prevents_duplicate_insert(self):
        store_id = self._create_store_for_fk()
        for _ in range(3):
            database.record_sent_email({
                'store_id': store_id,
                'store_name': 'Test',
                'order_id': '1001',
                'order_number': '#1001',
                'customer_email': 'c@test.com',
            })
        emails, total = database.get_sent_emails()
        assert total == 1

    def test_different_orders_both_insert(self):
        store_id = self._create_store_for_fk()
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1001', 'order_number': '#1001',
            'customer_email': 'c@test.com',
        })
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1002', 'order_number': '#1002',
            'customer_email': 'c@test.com',
        })
        _, total = database.get_sent_emails()
        assert total == 2

    def test_pagination(self):
        store_id = self._create_store_for_fk()
        for i in range(75):
            database.record_sent_email({
                'store_id': store_id, 'store_name': 'T',
                'order_id': str(i), 'order_number': f'#{i}',
                'customer_email': f'c{i}@test.com',
            })
        page1, total = database.get_sent_emails(page=1, per_page=50)
        assert total == 75
        assert len(page1) == 50

        page2, _ = database.get_sent_emails(page=2, per_page=50)
        assert len(page2) == 25

    def test_filter_by_store(self):
        s1 = database.create_store(_make_store(name='Store A'))
        s2 = database.create_store(_make_store(name='Store B'))
        database.record_sent_email({
            'store_id': s1, 'store_name': 'A',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'a@t.com',
        })
        database.record_sent_email({
            'store_id': s2, 'store_name': 'B',
            'order_id': '2', 'order_number': '#2',
            'customer_email': 'b@t.com',
        })
        results, total = database.get_sent_emails(store_id=s1)
        assert total == 1
        assert results[0]['store_name'] == 'A'

    def test_email_stats(self):
        store_id = self._create_store_for_fk()
        for i in range(5):
            database.record_sent_email({
                'store_id': store_id, 'store_name': 'T',
                'order_id': str(i), 'order_number': f'#{i}',
                'customer_email': f'c{i}@test.com',
            })
        stats = database.get_email_stats()
        assert stats['today_count'] == 5
        assert stats['week_count'] == 5
        assert stats['total_count'] == 5

    def test_export(self):
        store_id = self._create_store_for_fk()
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'c@t.com',
        })
        emails = database.get_all_sent_emails_for_export()
        assert len(emails) == 1

    def test_negative_page_doesnt_crash(self):
        """BUG: page=0 or page=-1 should not crash."""
        store_id = self._create_store_for_fk()
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'c@t.com',
        })
        # Should not crash
        results, total = database.get_sent_emails(page=0, per_page=50)
        assert total == 1

        results, total = database.get_sent_emails(page=-1, per_page=50)
        assert total == 1


class TestForeignKeyConstraint:
    def test_delete_store_with_fk_still_fails(self):
        """delete_store() without cascade still raises FK error (by design)."""
        store_id = database.create_store(_make_store())
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'c@t.com',
        })
        with pytest.raises(Exception):
            database.delete_store(store_id)

    def test_delete_store_cascade_works(self):
        """FIXED: delete_store_cascade() removes sent_emails first, then store."""
        store_id = database.create_store(_make_store())
        database.record_sent_email({
            'store_id': store_id, 'store_name': 'T',
            'order_id': '1', 'order_number': '#1',
            'customer_email': 'c@t.com',
        })
        database.delete_store_cascade(store_id)
        assert database.get_store(store_id) is None
        emails, total = database.get_sent_emails(store_id=store_id)
        assert total == 0

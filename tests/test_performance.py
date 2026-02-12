"""Load and performance tests."""
import os
import time
import tempfile
import threading
import pytest

_tmpdir = tempfile.mkdtemp()
os.environ['DATABASE_PATH'] = os.path.join(_tmpdir, 'test_perf.db')
os.environ['TEMPLATES_PATH'] = os.path.join(_tmpdir, 'templates')
os.environ['ADMIN_PASSWORD'] = 'testpass'
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['SENDGRID_API_KEY'] = 'SG.test'

os.makedirs(os.environ['TEMPLATES_PATH'], exist_ok=True)
with open(os.path.join(os.environ['TEMPLATES_PATH'], 'example.html'), 'w') as f:
    f.write('<h1>{{ store_name }}</h1>')

from app import app
from src import database


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
    client.post('/login', data={'password': 'testpass'})
    return client


class TestLargeDatasets:
    def test_create_100_stores(self, auth_client):
        """Create 100 stores and verify list page still works."""
        for i in range(100):
            database.create_store({
                'name': f'Store {i:03d}',
                'parcel_panel_api_key': f'pk-{i}',
                'shopify_store_url': f's{i}.myshopify.com',
                'shopify_admin_api_token': f'shpat_{i}',
                'from_email': f's{i}@test.com',
                'from_name': f'Team {i}',
                'email_subject': 'Test',
                'email_template': 'example.html',
            })
        stores = database.get_all_stores()
        assert len(stores) == 100

        start = time.time()
        resp = auth_client.get('/stores')
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0, f"Stores page took {elapsed:.2f}s (should be <2s)"

    def test_1000_sent_emails_pagination(self, auth_client):
        """Insert 1000 sent emails, verify pagination performance."""
        store_id = database.create_store({
            'name': 'Perf Store',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'a@b.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })
        for i in range(1000):
            database.record_sent_email({
                'store_id': store_id,
                'store_name': 'Perf Store',
                'order_id': str(i),
                'order_number': f'#{i}',
                'customer_email': f'c{i}@test.com',
                'tracking_number': f'YT{i}',
                'tracking_status': 'PENDING',
                'days_waiting': 10,
            })

        # Test pagination speed
        start = time.time()
        resp = auth_client.get('/logs')
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0, f"Logs page took {elapsed:.2f}s with 1000 records"

        # Test last page
        start = time.time()
        resp = auth_client.get('/logs?page=20')
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0

        # Test CSV export with 1000 records
        start = time.time()
        resp = auth_client.get('/logs/export')
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 3.0, f"CSV export took {elapsed:.2f}s with 1000 records"
        lines = resp.data.decode().strip().split('\n')
        assert len(lines) == 1001  # header + 1000

    def test_dashboard_with_many_stores(self, auth_client):
        """Dashboard should render fast even with many stores."""
        for i in range(50):
            sid = database.create_store({
                'name': f'Dash Store {i}',
                'parcel_panel_api_key': f'k-{i}',
                'shopify_store_url': f'ds{i}.myshopify.com',
                'shopify_admin_api_token': f't-{i}',
                'from_email': f'd{i}@t.com',
                'from_name': f'D {i}',
                'email_subject': 'S',
                'email_template': 'example.html',
            })
            for j in range(10):
                database.record_sent_email({
                    'store_id': sid, 'store_name': f'Dash Store {i}',
                    'order_id': f'{i}-{j}', 'order_number': f'#{i}-{j}',
                    'customer_email': f'c{i}-{j}@t.com',
                })

        start = time.time()
        resp = auth_client.get('/')
        elapsed = time.time() - start
        assert resp.status_code == 200
        assert elapsed < 2.0, f"Dashboard took {elapsed:.2f}s with 50 stores, 500 emails"


class TestConcurrency:
    def test_concurrent_reads(self, auth_client):
        """Multiple concurrent reads should not crash SQLite."""
        database.create_store({
            'name': 'Concurrent Store',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'a@b.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })

        errors = []

        def make_request():
            try:
                with app.test_client() as c:
                    c.post('/login', data={'password': 'testpass'})
                    for _ in range(10):
                        resp = c.get('/stores')
                        if resp.status_code != 200:
                            errors.append(f"Got {resp.status_code}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=make_request) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent read errors: {errors}"

    def test_concurrent_writes(self, auth_client):
        """Multiple concurrent writes should not lose data (WAL mode)."""
        errors = []

        def create_stores(start):
            try:
                for i in range(10):
                    database.create_store({
                        'name': f'Thread-{start}-Store-{i}',
                        'parcel_panel_api_key': f'k-{start}-{i}',
                        'shopify_store_url': f't{start}-{i}.myshopify.com',
                        'shopify_admin_api_token': f't-{start}-{i}',
                        'from_email': f't{start}-{i}@t.com',
                        'from_name': f'T {start}-{i}',
                        'email_subject': 'S',
                        'email_template': 'example.html',
                    })
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=create_stores, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent write errors: {errors}"
        stores = database.get_all_stores()
        assert len(stores) == 50, f"Expected 50 stores, got {len(stores)}"

    def test_concurrent_read_write(self, auth_client):
        """Concurrent reads and writes should not deadlock."""
        store_id = database.create_store({
            'name': 'RW Store',
            'parcel_panel_api_key': 'k',
            'shopify_store_url': 's.com',
            'shopify_admin_api_token': 't',
            'from_email': 'a@b.com',
            'from_name': 'T',
            'email_subject': 'S',
            'email_template': 'example.html',
        })
        errors = []

        def writer():
            try:
                for i in range(20):
                    database.record_sent_email({
                        'store_id': store_id, 'store_name': 'RW Store',
                        'order_id': str(i), 'order_number': f'#{i}',
                        'customer_email': f'c{i}@t.com',
                    })
            except Exception as e:
                errors.append(f"writer: {e}")

        def reader():
            try:
                for _ in range(20):
                    database.get_sent_emails()
                    database.get_email_stats()
            except Exception as e:
                errors.append(f"reader: {e}")

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Concurrent R/W errors: {errors}"

import unittest
import sqlite3
import time
from zerotrust.server import store

class TestStore(unittest.TestCase):
    def setUp(self):
        # KURAL: :memory: in-memory veritabanı kullan
        self.conn = store.open_connection(":memory:")
        store.init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_schema_idempotent(self):
        """
        KURAL: Schema creation is idempotent.
        Arka arkaya init_schema çağrıldığında hata vermemeli.
        """
        try:
            store.init_schema(self.conn)
            store.init_schema(self.conn)
        except Exception as e:
            self.fail(f"init_schema is not idempotent! Raised: {e}")

    def test_insert_fetch_round_trip(self):
        """
        KURAL: Insert / fetch round-trip. Tüm sütunların bit-for-bit, 
        özellikle BLOB alanlarının bytes olarak aynı döndüğü test edilmeli.
        """
        row = {
            'file_id': 'f1',
            'sender_id': 'alice',
            'recipient_id': 'bob',
            'upload_timestamp': int(time.time()),
            'expiration': int(time.time()) + 3600,
            'status': 'pending',
            'ciphertext_path': '/path/to/cipher',
            'ciphertext_sha256': 'fake_sha256',
            'wrapped_key': b'\x00\x01\x02key',        # BLOB bytes test
            'aes_nonce': b'\x03\x04nonce',            # BLOB bytes test
            'aes_aad': b'\x05aad',                    # BLOB bytes test
            'sender_signature': b'\x06\x07signature', # BLOB bytes test
            'sender_cert_json': '{"cert": "data"}'
        }
        
        store.insert_file(self.conn, row)
        
        fetched = store.get_file(self.conn, 'f1')
        self.assertIsNotNone(fetched, "File could not be fetched after insert.")
        
        # 13 Sütunun her birinin orijinaliyle birebir aynı değer ve aynı tipte döndüğünden emin ol
        for key, expected_value in row.items():
            self.assertEqual(fetched[key], expected_value, f"Mismatch at column {key}")
            self.assertIsInstance(fetched[key], type(expected_value), f"Type mismatch at column {key}")

    def test_recipient_isolation(self):
        """
        KURAL: Recipient isolation. Alice'in listesinde Bob'un dosyaları gelmemeli.
        """
        row_alice = {
            'file_id': 'f_alice',
            'sender_id': 'charlie',
            'recipient_id': 'alice',
            'upload_timestamp': int(time.time()),
            'expiration': int(time.time()) + 3600,
            'ciphertext_path': 'p1',
            'ciphertext_sha256': 'h1',
            'wrapped_key': b'k1',
            'aes_nonce': b'n1',
            'aes_aad': b'a1',
            'sender_signature': b's1',
            'sender_cert_json': 'j1'
        }
        
        row_bob = dict(row_alice)
        row_bob['file_id'] = 'f_bob'
        row_bob['recipient_id'] = 'bob'
        
        store.insert_file(self.conn, row_alice)
        store.insert_file(self.conn, row_bob)
        
        # Sadece Alice için bekleyenleri listele
        alice_files = store.list_pending_for(self.conn, 'alice')
        
        self.assertEqual(len(alice_files), 1, "Alice should only have 1 pending file")
        self.assertEqual(alice_files[0]['file_id'], 'f_alice')
        self.assertEqual(alice_files[0]['recipient_id'], 'alice')

    def test_expired_filter(self):
        """
        KURAL: Expired filter. Süresi dolmuş dosyalar list_pending_for'da yer almamalı.
        """
        expired_time = int(time.time()) - 100 # Geçmişte bir zaman
        row = {
            'file_id': 'f_expired',
            'sender_id': 'charlie',
            'recipient_id': 'alice',
            'upload_timestamp': int(time.time()) - 200,
            'expiration': expired_time,
            'ciphertext_path': 'p',
            'ciphertext_sha256': 'h',
            'wrapped_key': b'k',
            'aes_nonce': b'n',
            'aes_aad': b'a',
            'sender_signature': b's',
            'sender_cert_json': 'j'
        }
        
        # Insert işlemi varsayılan olarak status='pending' atayacak.
        store.insert_file(self.conn, row)
        
        # Alice dosyalarını listelediğinde zamanı geçtiği için boş dönmeli
        alice_files = store.list_pending_for(self.conn, 'alice')
        self.assertEqual(len(alice_files), 0, "Expired files MUST NOT be included in pending lists!")

    def test_invalid_status(self):
        """
        KURAL: Invalid status. mark_status geçerli tuple dışında bir değer alırsa ValueError fırlatmalı.
        """
        row = {
            'file_id': 'f1',
            'sender_id': 'alice',
            'recipient_id': 'bob',
            'upload_timestamp': int(time.time()),
            'expiration': int(time.time()) + 3600,
            'ciphertext_path': 'p',
            'ciphertext_sha256': 'h',
            'wrapped_key': b'k',
            'aes_nonce': b'n',
            'aes_aad': b'a',
            'sender_signature': b's',
            'sender_cert_json': 'j'
        }
        store.insert_file(self.conn, row)
        
        with self.assertRaises(ValueError):
            store.mark_status(self.conn, 'f1', 'invalid_status')
            
        # Doğru bir status geçelim, hata vermemesi lazım
        try:
            store.mark_status(self.conn, 'f1', 'downloaded')
        except ValueError:
            self.fail("Valid status 'downloaded' raised ValueError incorrectly.")

if __name__ == '__main__':
    unittest.main()

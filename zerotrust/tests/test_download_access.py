import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from zerotrust.client.download import download_file
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.common.exceptions import ProtocolError, AuthError

class TestDownloadAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir_obj = tempfile.TemporaryDirectory()
        cls.test_dir = Path(cls.test_dir_obj.name)
        
        # 1. CA ve Client kurulumu
        cls.ca_dir = cls.test_dir / "ca"
        subprocess.run(["python", "-m", "zerotrust.ca.ca", "init", "--out", str(cls.ca_dir), "--password", "ca_pass"], check=True)
        
        for user in ["alice", "bob", "carol"]:
            user_dir = cls.test_dir / f"client_{user}"
            user_dir.mkdir()
            subprocess.run([
                "python", "-m", "zerotrust.ca.ca", "issue", user, 
                "--ca-dir", str(cls.ca_dir), 
                "--user-dir", str(cls.test_dir), 
                "--password", "ca_pass", 
                "--user-password", "user_pass"
            ], check=True)
            
            shutil.move(str(cls.test_dir / user / "private.pem"), str(user_dir / "private.pem"))
            shutil.move(str(cls.test_dir / user / "public.pem"), str(user_dir / "public.pem"))
            shutil.move(str(cls.test_dir / user / "cert.json"), str(user_dir / "cert.json"))
            shutil.rmtree(str(cls.test_dir / user))
            
            shutil.copy(cls.ca_dir / "ca_cert.json", user_dir / "ca_cert.json")
            config = {
                "server_host": "127.0.0.1",
                "server_port": 0,
                "username": user
            }
            (user_dir / "config.json").write_text(json.dumps(config))
            
        # 2. Server ayarlamalari
        cls.server_dir = cls.test_dir / "server"
        cls.server_dir.mkdir()
        cls.pubkeys_dir = cls.server_dir / "pubkeys"
        cls.pubkeys_dir.mkdir()
        
        for user in ["alice", "bob", "carol"]:
            shutil.copy(cls.test_dir / f"client_{user}" / "cert.json", cls.pubkeys_dir / f"{user}.json")
            
        subprocess.run([
            "python", "-m", "zerotrust.ca.ca", "issue", "server", 
            "--ca-dir", str(cls.ca_dir), 
            "--user-dir", str(cls.server_dir), 
            "--password", "ca_pass", 
            "--user-password", "demo-password"
        ], check=True)
        
        cls.db_path = str(cls.server_dir / "metadata.db")
        server_state = {
            "cert_path": str(cls.server_dir / "server" / "cert.json"),
            "key_path": str(cls.server_dir / "server" / "private.pem"),
            "ca_cert_path": str(cls.ca_dir / "ca_cert.json"),
            "db_path": cls.db_path,
            "server_password": b"demo-password",
        }
        
        from zerotrust.server.main import ZeroTrustServer, ZeroTrustRequestHandler
        cls.server = ZeroTrustServer(('127.0.0.1', 0), ZeroTrustRequestHandler, server_state)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        
        for user in ["alice", "bob", "carol"]:
            config_path = cls.test_dir / f"client_{user}" / "config.json"
            config = json.loads(config_path.read_text())
            config["server_port"] = cls.port
            config_path.write_text(json.dumps(config))
            
        os.environ["ZEROTRUST_SERVER_HOST"] = "127.0.0.1"
        os.environ["ZEROTRUST_SERVER_PORT"] = str(cls.port)
        
        cls.secret_txt = cls.test_dir / "secret.txt"
        cls.secret_txt.write_text("Top secret message.")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server_thread.join(timeout=1.0)
        cls.server.server_close()
        cls.test_dir_obj.cleanup()

    def setUp(self):
        self.original_cwd = os.getcwd()
        os.chdir(str(self.test_dir))

        # Alice -> Bob upload
        with connected_session("alice", b"user_pass") as session:
            ack = upload_file(session, "bob", str(self.secret_txt), expiration_seconds=3600)
            self.file_id = ack["file_id"]

    def tearDown(self):
        os.chdir(self.original_cwd)

    def test_happy_path(self):
        """Happy path: Bob dosyayı sorunsuzca indirebilmeli."""
        with connected_session("bob", b"user_pass") as session:
            download_file(session, self.file_id)
        
        # Inmis mi bakalim
        self.assertTrue((Path("client_bob") / "downloads" / self.file_id).is_file())

    def test_wrong_recipient(self):
        """Wrong recipient: recipient_id='bob', ancak peer_subject='carol'."""
        with connected_session("carol", b"user_pass") as session:
            with self.assertRaises(ProtocolError) as ctx:
                download_file(session, self.file_id)
            self.assertEqual(str(ctx.exception), "AUTH_FAILED")

    def test_expired(self):
        """Expired: Veritabanından expiration geriye alınır (süresi dolmuş)."""
        # Suanki zamanin oncesine alalim
        from zerotrust.server.store import open_connection, get_file
        conn = open_connection(self.db_path)
        with conn:
            conn.execute("UPDATE files SET expiration = ? WHERE file_id = ?", (int(time.time()) - 3600, self.file_id))
        conn.close()
        
        with connected_session("bob", b"user_pass") as session:
            with self.assertRaises(ProtocolError) as ctx:
                download_file(session, self.file_id)
            self.assertEqual(str(ctx.exception), "EXPIRED")
            
        # Opportunistic guncelleme veritabanina isledi mi?
        from zerotrust.server.store import open_connection, get_file
        conn = open_connection(self.db_path)
        record = get_file(conn, self.file_id)
        conn.close()
        
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "expired")

    def test_not_found(self):
        """Not found: Veritabanında olmayan UUID ile istek."""
        import uuid
        fake_uuid = str(uuid.uuid4())
        
        with connected_session("bob", b"user_pass") as session:
            with self.assertRaises(ProtocolError) as ctx:
                download_file(session, fake_uuid)
            self.assertEqual(str(ctx.exception), "NOT_FOUND")

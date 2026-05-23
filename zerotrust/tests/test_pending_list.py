import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from zerotrust.client.download import list_pending
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.server.store import open_connection, mark_expired

class TestPendingList(unittest.TestCase):
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
        # Klasik cwd degisimi client_ klasorlerini bulmak icin (test_download.py gibi)
        self.original_cwd = os.getcwd()
        os.chdir(str(self.test_dir))

    def tearDown(self):
        os.chdir(self.original_cwd)
        
        # Testten sonra DB'yi temizleyelim ki diger testleri etkilemesin
        conn = open_connection(self.db_path)
        with conn:
            conn.execute("DELETE FROM files")
        conn.close()

    def test_happy_path_listing(self):
        """Happy path: Başarılı bir yükleme sonrası listenin 1 satır dönmesi."""
        # Alice, Bob'a dosya yollar
        with connected_session("alice", b"user_pass") as session:
            ack = upload_file(session, "bob", str(self.secret_txt))
            
        # Bob listeler
        with connected_session("bob", b"user_pass") as session:
            files = list_pending(session)
            
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["file_id"], ack["file_id"])
        self.assertEqual(files[0]["sender_id"], "alice")
        self.assertIn("size", files[0])
        self.assertGreater(files[0]["size"], 0)

    def test_isolation(self):
        """Isolation: Alice, Bob'a dosya attığında Carol listeleme yaparsa liste BOŞ dönmeli."""
        with connected_session("alice", b"user_pass") as session:
            upload_file(session, "bob", str(self.secret_txt))
            
        # Carol listeler
        with connected_session("carol", b"user_pass") as session:
            files = list_pending(session)
            
        self.assertEqual(len(files), 0, "Carol cannot see Bob's files!")

    def test_expired_filter(self):
        """Expired filter: Dosya süresi geçmişse listede GÖZÜKMEMESİ."""
        with connected_session("alice", b"user_pass") as session:
            # Suresi hemen dolacak bir dosya (mesela 0 seconds - wait upload_file uses days by default, we can just manipulate db)
            ack = upload_file(session, "bob", str(self.secret_txt))
            
        # DB ye mudahale edip force-expire (gecmis zamana aliyoruz)
        conn = open_connection(self.db_path)
        with conn:
            conn.execute("UPDATE files SET expiration = ? WHERE file_id = ?", (int(time.time()) - 3600, ack["file_id"]))
            
        # mark_expired calistir
        mark_expired(conn)
        conn.close()
        
        # Bob listeler
        with connected_session("bob", b"user_pass") as session:
            files = list_pending(session)
            
        self.assertEqual(len(files), 0, "Expired files should not be listed!")

    def test_replay_idempotent(self):
        """Replay: Üst üste iki listeleme isteğinin de başarıyla çalışması."""
        with connected_session("alice", b"user_pass") as session:
            upload_file(session, "bob", str(self.secret_txt))
            
        with connected_session("bob", b"user_pass") as session:
            files1 = list_pending(session)
            files2 = list_pending(session)
            
        self.assertEqual(len(files1), 1)
        self.assertEqual(files1, files2, "Subsequent LIST requests should yield identical results")

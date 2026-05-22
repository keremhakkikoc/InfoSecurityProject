import base64
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import subprocess
from zerotrust.client.download import download_file
from zerotrust.client.session import connected_session
from zerotrust.client.upload import upload_file
from zerotrust.common.exceptions import ProtocolError, ZeroTrustError
from zerotrust.server.store import open_connection

class TestSecureDownload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Kendi CA'mizi ve test kullanicilarini yaratalim
        cls.test_dir = Path(tempfile.mkdtemp())
        cls.ca_dir = cls.test_dir / "ca_data"
        cls.ca_dir.mkdir()
        
        # init CA
        subprocess.run(["python", "-m", "zerotrust.ca.ca", "init", "--out", str(cls.ca_dir), "--password", "ca_pass"], check=True)
        
        # alice, bob, mallory yarat (client_<user> formatında)
        for user in ["alice", "bob", "mallory"]:
            user_dir = cls.test_dir / f"client_{user}"
            user_dir.mkdir()
            subprocess.run(["python", "-m", "zerotrust.ca.ca", "issue", user, "--ca-dir", str(cls.ca_dir), "--user-dir", str(cls.test_dir), "--password", "ca_pass", "--user-password", "user_pass"], check=True)
            # CA issue komutu, --user-dir/user altinda yaratir, onu tasiyalim:
            shutil.move(str(cls.test_dir / user / "private.pem"), str(user_dir / "private.pem"))
            shutil.move(str(cls.test_dir / user / "public.pem"), str(user_dir / "public.pem"))
            shutil.move(str(cls.test_dir / user / "cert.json"), str(user_dir / "cert.json"))
            shutil.rmtree(str(cls.test_dir / user))
            
            # config.json ve ca_cert.json ekle
            shutil.copy(cls.ca_dir / "ca_cert.json", user_dir / "ca_cert.json")
            config = {
                "server_host": "127.0.0.1",
                "server_port": 0, # Portu sonra guncelleyecegiz, ama server basladiktan sonra
                "username": user
            }
            (user_dir / "config.json").write_text(json.dumps(config))
            
        # 2. Server ayarlamalari
        cls.server_dir = cls.test_dir / "server"
        cls.server_dir.mkdir()
        cls.pubkeys_dir = cls.server_dir / "pubkeys"
        cls.pubkeys_dir.mkdir()
        
        # Kullanıcıların pubkey certlerini server/pubkeys altina kopyala
        for user in ["alice", "bob", "mallory"]:
            shutil.copy(cls.test_dir / f"client_{user}" / "cert.json", cls.pubkeys_dir / f"{user}.json")
            
        # server cert yarat
        subprocess.run(["python", "-m", "zerotrust.ca.ca", "issue", "server", "--ca-dir", str(cls.ca_dir), "--user-dir", str(cls.server_dir), "--password", "ca_pass", "--user-password", "demo-password"], check=True)
        # Server dosyalari server/server/ icine cikarildi. onlari server/ altina purgeliyelim
        shutil.copy(cls.server_dir / "server" / "cert.json", cls.server_dir / "cert.json")
        shutil.copy(cls.server_dir / "server" / "private.pem", cls.server_dir / "private.pem")
        
        db_path = cls.server_dir / "metadata.db"
        
        server_state = {
            "upload_dir": str(cls.server_dir / "data"),
            "db_path": str(db_path),
            "cert_path": str(cls.server_dir / "cert.json"),
            "key_path": str(cls.server_dir / "private.pem"),
            "ca_cert_path": str(cls.ca_dir / "ca_cert.json"),
            "server_password": b"demo-password"
        }
        
        # Server'i baslat
        from zerotrust.server.main import ZeroTrustServer, ZeroTrustRequestHandler
        cls.server = ZeroTrustServer(('127.0.0.1', 0), ZeroTrustRequestHandler, server_state)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        
        # Simdi port belli olduguna gore config.json'lari guncelleyelim
        for user in ["alice", "bob", "mallory"]:
            config_path = cls.test_dir / f"client_{user}" / "config.json"
            config = json.loads(config_path.read_text())
            config["server_port"] = cls.port
            config_path.write_text(json.dumps(config))
            
        # ZEROTRUST_SERVER_HOST env var ayari, client_cli ve upload_file'in baglanacagi yeri gosterir
        os.environ["ZEROTRUST_SERVER_HOST"] = "127.0.0.1"
        os.environ["ZEROTRUST_SERVER_PORT"] = str(cls.port)
        
        # Testlerde kullanacagimiz sir sakli dosyamiz
        cls.secret_txt = cls.test_dir / "secret.txt"
        cls.secret_txt.write_bytes(b"Top secret message from Alice to Bob!")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()
        shutil.rmtree(cls.test_dir)
        os.environ.pop("ZEROTRUST_SERVER_HOST", None)
        os.environ.pop("ZEROTRUST_SERVER_PORT", None)

    def setUp(self):
        # Her testten once CWD'yi patch et ki client cli dogru keyleri bulsun.
        # Biz test_dir i CWD yaparsak client.session -> users/{username} diye bulur.
        self._orig_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Alice, Bob'a dosya yukler
        with connected_session("alice", b"user_pass") as session:
            ack = upload_file(session, "bob", str(self.secret_txt))
            self.file_id = ack["file_id"]

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_happy_path_download(self):
        """Doğru alıcı paketi indirir, başarıyla deşifre eder ve diske yazar."""
        with connected_session("bob", b"user_pass") as session:
            download_file(session, self.file_id)
            
        # Dosya diskte olmalı
        downloaded_file = Path(f"client_bob/downloads/{self.file_id}")
        self.assertTrue(downloaded_file.exists())
        self.assertEqual(downloaded_file.read_bytes(), b"Top secret message from Alice to Bob!")

    def test_unauthorized_access(self):
        """Alice'in dosyasına Mallory erişmeye çalışır -> Sunucu AUTH_FAILED döner."""
        with connected_session("mallory", b"user_pass") as session:
            with self.assertRaises(ProtocolError) as ctx:
                download_file(session, self.file_id)
            self.assertIn("AUTH_FAILED", str(ctx.exception))
            
        # Dosya mallory'ye inmemis olmali
        downloaded_file = Path(f"client_mallory/downloads/{self.file_id}")
        self.assertFalse(downloaded_file.exists())

    def test_tampered_ciphertext(self):
        """Sunucu ile istemci arasında ciphertext bozulursa (MITM) -> AES-GCM tag kontrolü patlar, dosya yazılmaz."""
        # SQLite a girip ciphertext_sha256 yi bozmadan dogrudan diski (blob) bozalim 
        # Server dosyayi okuyup gonderecek, client decrypt ederken GCM tag patlayacak
        final_path = self.server_dir / "files" / f"{self.file_id}.bin"
        content = bytearray(final_path.read_bytes())
        content[0] ^= 0xFF # İlk baytı boz
        final_path.write_bytes(content)
        
        with connected_session("bob", b"user_pass") as session:
            with self.assertRaises(ZeroTrustError) as ctx:
                download_file(session, self.file_id)
            self.assertIn("authentication failed", str(ctx.exception).lower())
            
        downloaded_file = Path(f"client_bob/downloads/{self.file_id}")
        self.assertFalse(downloaded_file.exists(), "Corrupted file must NOT be written to disk!")

    def test_forged_signature(self):
        """İmza geçerli değilse -> İstemci dosyayı reddeder."""
        # Bu senaryoda serverdaki veritabaninda signature alanini bozalim (MITM)
        db_path = str(self.server_dir / "metadata.db")
        conn = open_connection(db_path)
        with conn:
            conn.execute("UPDATE files SET sender_signature = ? WHERE file_id = ?", (b"fake_signature_bytes", self.file_id))
        conn.close()
        
        with connected_session("bob", b"user_pass") as session:
            with self.assertRaises(ZeroTrustError) as ctx:
                download_file(session, self.file_id)
            self.assertIn("signature validation failed", str(ctx.exception).lower())
            
        downloaded_file = Path(f"client_bob/downloads/{self.file_id}")
        self.assertFalse(downloaded_file.exists())

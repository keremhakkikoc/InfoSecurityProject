import time
import socket
import threading
import unittest
import struct
from zerotrust.server.main import ZeroTrustServer, ZeroTrustRequestHandler

class TestServerBoot(unittest.TestCase):
    def setUp(self):
        # KURAL: Testlerde port çakışmasını önlemek için Ephemeral port (0) kullan.
        # Sertifikalar main.py'deki main() içinde kontrol ediliyor, server init'te degil.
        # Bu yüzden server'ı test ederken sahte bir server_state verebiliriz.
        server_state = {}
        self.server = ZeroTrustServer(('127.0.0.1', 0), ZeroTrustRequestHandler, server_state)
        self.port = self.server.server_address[1]
        
        # Sunucuyu arka planda calistir
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()

    def test_multithreading_concurrent_clients(self):
        """
        KURAL: threading.Event kullanarak iki istemcinin aynı anda bağlanabildiğini, 
        yavaş olanın hızlı olanı bloklamadığını test et.
        """
        event_slow_client_connected = threading.Event()
        event_fast_client_done = threading.Event()

        def slow_client():
            # Yavaş istemci: Bağlanıp bilerek bekliyor
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(('127.0.0.1', self.port))
                    event_slow_client_connected.set()
                    
                    # Hizli istemcinin isini bitirmesini bekle
                    success = event_fast_client_done.wait(timeout=5)
                    self.assertTrue(success, "Hizli istemci zamaninda islemini bitiremedi (Bloke oldu!)")
            except Exception as e:
                self.fail(f"Yavas istemci hatasi: {e}")

        def fast_client():
            # Hızlı istemci: Yavaş olan bağlandıktan sonra bağlanıp işini hemen bitiriyor
            try:
                # Yavasin sunucuya baglanmasini bekle
                event_slow_client_connected.wait(timeout=2)
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(('127.0.0.1', self.port))
                    sock.sendall(b"Hello from fast client")
                
                # İşim bitti, eventi tetikle
                event_fast_client_done.set()
            except Exception as e:
                self.fail(f"Hizli istemci hatasi: {e}")

        t1 = threading.Thread(target=slow_client)
        t2 = threading.Thread(target=fast_client)
        
        t1.start()
        t2.start()
        
        t1.join(timeout=3)
        t2.join(timeout=3)
        
        self.assertTrue(event_fast_client_done.is_set(), "Multithreading calismiyor, sunucu bloklandi.")

    def test_negative_path_broken_connection(self):
        """
        KURAL: Yarıda kesilen bağlantının (conn.close() mid-read) sunucuyu 
        çökertmediğini test eden "Negative Path" senaryosu.
        """
        # Istemci baglanir ve hemen socket'i sert bir sekilde kapatir
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', self.port))
            # Hicbir sey gondermeden baglantiyi acimasizca kapat (mid-read senaryosu)
            # Linger set edilerek hard close yapilabilir
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            sock.close()
        except Exception as e:
            self.fail(f"Negative path istemci baglanti hatasi: {e}")

        # Sunucu hala ayakta mi kontrol etmek icin normal bir baglanti yapalim
        time.sleep(0.1) # Sunucunun hata logunu yazmasi icin kisa bir bekleme
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                sock2.connect(('127.0.0.1', self.port))
                sock2.sendall(b"Test if alive")
        except Exception as e:
            self.fail(f"Negative path testi sonrasi sunucu coktu: {e}")

if __name__ == '__main__':
    unittest.main()

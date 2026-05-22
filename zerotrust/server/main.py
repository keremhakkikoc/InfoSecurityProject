import argparse
import logging
import os
import socketserver
import sys

from zerotrust.server.handler import serve_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("server.main")

class ZeroTrustRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # socketserver.ThreadingTCPServer her yeni bağlantı için yeni bir thread'de
        # bu metodu çağırır.
        # self.request -> sock, self.client_address -> addr, self.server -> server instance
        serve_connection(self.request, self.client_address, self.server.server_state)

class ZeroTrustServer(socketserver.ThreadingTCPServer):
    # KURAL: Thread'ler "Daemon thread" olmalı.
    daemon_threads = True
    # Portun işletim sistemi tarafından hemen tekrar kullanılabilmesi için
    allow_reuse_address = True

    def __init__(self, server_address, request_handler_class, server_state):
        super().__init__(server_address, request_handler_class)
        self.server_state = server_state

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust Secure File Drop Server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5050, help="Server port (default: 5050)")
    parser.add_argument("--db", type=str, default="zerotrust/server/storage/metadata.db", help="SQLite DB path")
    parser.add_argument("--ca-cert", type=str, default="ca_data/ca_cert.json", help="CA certificate path")
    parser.add_argument("--cert", type=str, default="users/server/cert.json", help="Server certificate (CA-signed JSON)")
    parser.add_argument("--key", type=str, default="users/server/private.pem", help="Server private key (encrypted PEM)")
    
    args = parser.parse_args()

    # KURAL: Server'ın kendi sertifikası ve private key'i yüklenmeli (PEM formatında). 
    # Eksikse başlatmayı reddet (hata fırlat).
    if not os.path.exists(args.cert):
        logger.error(f"Kritik Hata: Sunucu sertifikasi ({args.cert}) bulunamadi!")
        sys.exit(1)
        
    if not os.path.exists(args.key):
        logger.error(f"Kritik Hata: Sunucu private key'i ({args.key}) bulunamadi!")
        sys.exit(1)
        
    logger.info("Sertifika ve anahtar dosyalari basariyla dogrulandi.")

    server_state = {
        'db_path': args.db,
        'ca_cert_path': args.ca_cert,
        'cert_path': args.cert,
        'key_path': args.key
    }

    server_address = (args.host, args.port)
    server = ZeroTrustServer(server_address, ZeroTrustRequestHandler, server_state)

    logger.info(f"[*] Sunucu baslatiliyor -> {args.host}:{args.port}")
    logger.info("Kapatmak icin CTRL+C (SIGINT) kullanin.")

    try:
        # KURAL: KESİNLİKLE select veya asyncio KULLANMA. socketserver.ThreadingTCPServer kullan.
        # Worker thread'lerde signal.signal() YASAKTIR. (sadece main thread'de handle edilir).
        server.serve_forever()
    except KeyboardInterrupt:
        # KURAL: Ana thread'de (main) SIGINT / KeyboardInterrupt yakala ve sunucuyu 
        # temiz bir şekilde kapat (graceful shutdown).
        logger.info("\n[*] SIGINT alindi. Sunucu temiz bir sekilde kapatiliyor...")
    except Exception as e:
        logger.error(f"Sunucu calisirken beklenmeyen hata: {e}")
    finally:
        server.shutdown()
        server.server_close()
        logger.info("[*] Sunucu kapandi.")

if __name__ == "__main__":
    main()

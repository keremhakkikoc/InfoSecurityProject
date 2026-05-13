import logging
import sqlite3

logger = logging.getLogger(__name__)

def serve_connection(sock, addr, server_state):
    """
    Handles a single client connection. This function runs in a dedicated worker thread.
    
    Args:
        sock (socket.socket): The client socket.
        addr (tuple): The client address (ip, port).
        server_state (dict): Shared server configuration and state.
    """
    logger.info(f"[*] Yeni baglanti kabul edildi: {addr}")
    
    # KURAL: Thread'ler arası SQLite bağlantısı paylaşmak YASAKTIR.
    # Her thread, veritabanı işlemlerini gerçekleştirmek için kendi sqlite3.Connection 
    # nesnesini açmalıdır. Aksi halde thread-safety sorunları ve "database is locked" 
    # hataları alınır. SQLite, varsayılan olarak multi-threading ortamlarda aynı 
    # bağlantının paylaşılmasını engeller.
    db_path = server_state.get('db_path', 'server/storage/metadata.db')
    # db_conn = sqlite3.connect(db_path)
    # try:
    #     ... veritabanı işlemleri ...
    # finally:
    #     db_conn.close()
    
    try:
        # Şimdilik sadece stub. Gelen isteği okuyup kapatıyoruz.
        # İleride burada handshake, authentication ve file-drop işlemleri olacak.
        data = sock.recv(1024)
        if data:
            logger.debug(f"[{addr}] Veri alindi: {len(data)} bytes")
            
    except Exception as e:
        # KURAL: En dışı try/except Exception: bloğu ile sarılmalı ki, 
        # bozuk bir istemci (bad client) sunucuyu çökertmesin.
        logger.error(f"[-] {addr} istemcisinde beklenmeyen hata: {e}")
    finally:
        try:
            sock.close()
            logger.info(f"[*] Baglanti kapatildi: {addr}")
        except Exception as e:
            logger.error(f"[-] {addr} baglantisi kapatilirken hata: {e}")

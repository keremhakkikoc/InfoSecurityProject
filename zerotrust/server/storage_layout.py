import os


def pubkey_path_for(storage_base: str, username: str) -> str:
    """
    Kullanıcının public key JSON dosyasının bulunduğu disk yolunu döndürür.
    Örnek: server/storage/pubkeys/<username>.json
    """
    return os.path.join(storage_base, "pubkeys", f"{username}.json")

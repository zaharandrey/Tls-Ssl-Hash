import ssl
import socket
import hashlib
import base64

def get_public_key_hash(hostname, port=443):
    try:
        # Підключення до сервера через TLS
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Отримання сертифіката
                cert = ssock.getpeercert(binary_form=True)

                # Завантаження сертифіката через ssl для аналізу
                cert_info = ssl.DER_cert_to_PEM_cert(cert)
                public_key = ssl.PEM_cert_to_DER_cert(cert_info)

                # Обчислення SHA-256 хешу публічного ключа
                public_key_hash = hashlib.sha256(public_key).digest()
                public_key_hash_base64 = base64.b64encode(public_key_hash).decode('utf-8')

                return public_key_hash_base64
    except ssl.SSLError as e:
        print(f"SSL помилка: {e}")
    except socket.error as e:
        print(f"Помилка сокета: {e}")
    except Exception as e:
        print(f"Інша помилка: {e}")

# Приклад виклику функції
if __name__ == "__main__":
    hostname = "www.google.com"  # Змініть на потрібний хост
    public_key_hash = get_public_key_hash(hostname)
    if public_key_hash:
        print(f"Хеш публічного ключа (SHA-256, Base64): {public_key_hash}")


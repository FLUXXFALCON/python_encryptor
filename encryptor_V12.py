import sys
import os
import py_compile
import base64
import zlib
import random
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    from cryptography import fernet
except ImportError:
    print("Hata: 'cryptography' gerekli. Kur: pip install cryptography")
    sys.exit(1)

class UltraObfuscatorConf:
    def __init__(self):
        self.salt = os.urandom(16)
        self.noise = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*", k=25))
        self.xor_key = os.urandom(32)
        self.aes_key = os.urandom(32)
        self.camellia_key = os.urandom(32)
        self.chacha_key = os.urandom(32)
        self.hmac_key = os.urandom(32)
        self.aes_nonce = os.urandom(16)
        self.camellia_nonce = os.urandom(16)
        self.chacha_nonce = os.urandom(12)
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
        self.chunk_size = 50000

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=self.salt,
            iterations=150000,
        )
        return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key_v6"))

    def _xor_layer(self, data):
        return bytes(a ^ b for a, b in zip(data, self.xor_key * (len(data) // len(self.xor_key) + 1)))

    def _aes_layer(self, data, encrypt=True):
        try:
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(self.aes_nonce))
            if encrypt:
                encryptor = cipher.encryptor()
                return encryptor.update(data) + encryptor.finalize()
            else:
                decryptor = cipher.decryptor()
                return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            raise Exception(f"AES hatası: {str(e)}")

    def _camellia_layer(self, data, encrypt=True):
        try:
            cipher = Cipher(algorithms.Camellia(self.camellia_key), modes.CTR(self.camellia_nonce))
            if encrypt:
                encryptor = cipher.encryptor()
                return encryptor.update(data) + encryptor.finalize()
            else:
                decryptor = cipher.decryptor()
                return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            raise Exception(f"Camellia hatası: {str(e)}")

    def _chacha_layer(self, data, encrypt=True):
        try:
            chacha = ChaCha20Poly1305(self.chacha_key)
            if encrypt:
                return chacha.encrypt(self.chacha_nonce, data, None)
            else:
                return chacha.decrypt(self.chacha_nonce, data, None)
        except Exception as e:
            raise Exception(f"ChaCha hatası: {str(e)}")

    def _hash_layer(self, data):
        md5 = hashes.Hash(hashes.MD5())
        md5.update(data)
        h1 = md5.finalize()
        sha256 = hashes.Hash(hashes.SHA256())
        sha256.update(h1)
        h2 = sha256.finalize()
        sha512 = hashes.Hash(hashes.SHA512())
        sha512.update(h2)
        h4 = sha512.finalize()
        return h4

    def _hmac_layer(self, data):
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def _scramble_layer(self, data):
        mid = len(data) // 2
        random.seed(binascii.hexlify(self.salt))
        parts = [data[:mid], data[mid:]]
        random.shuffle(parts)
        return b''.join(parts)

    def _chunk_data(self, data, encrypt=True):
        chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
        if encrypt:
            return b''.join(base64.b85encode(chunk) for chunk in chunks)
        else:
            return b''.join(base64.b85decode(chunk) for chunk in chunks)

    def hide_code(self, code):
        try:
            # Ham string kodu baytlara çevirip şifrelemeye başlıyoruz
            code_bytes = code.encode('utf-8')  # String -> bytes
            chacha_encrypted = self._chacha_layer(code_bytes, encrypt=True)  # 1. ChaCha20-Poly1305
            compressed = zlib.compress(chacha_encrypted, level=9)            # 2. Zlib
            scrambled = self._scramble_layer(compressed)                    # 3. Scramble
            camellia_encrypted = self._camellia_layer(scrambled, encrypt=True)  # 4. Camellia
            aes_encrypted = self._aes_layer(camellia_encrypted, encrypt=True)   # 5. AES
            xor_obfuscated = self._xor_layer(aes_encrypted)                 # 6. XOR
            fernet_encrypted = self.cipher.encrypt(xor_obfuscated)          # 7. Fernet
            hash_tag = self._hash_layer(fernet_encrypted)                   # 8. Hash (SHA512)
            hmac_tag = self._hmac_layer(fernet_encrypted + hash_tag)        # 9. HMAC
            combined = fernet_encrypted + hash_tag + hmac_tag
            hexed = binascii.hexlify(combined)                              # 10. Hex
            b85_chunks = self._chunk_data(hexed, encrypt=True)              # 11. Base85
            encoded = base64.b64encode(b85_chunks).decode('utf-8')          # 12. Base64
            return encoded
        except Exception as e:
            print(f"Gizleme hatası: {str(e)}")
            sys.exit(1)

    def create_hidden_script(self, input_file, output_file):
        if not os.path.exists(input_file):
            print(f"Hata: '{input_file}' bulunamadı!")
            sys.exit(1)

        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                original_code = f.read()

            hidden_code = self.hide_code(original_code)

            wrapper_code = f"""import sys
import base64
import zlib
import random
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

{random.randint(100000, 999999)}
SALT = {repr(self.salt)}
NOISE = "{self.noise}"
XOR_KEY = {repr(self.xor_key)}
AES_KEY = {repr(self.aes_key)}
CAMELLIA_KEY = {repr(self.camellia_key)}
CHACHA_KEY = {repr(self.chacha_key)}
HMAC_KEY = {repr(self.hmac_key)}
AES_NONCE = {repr(self.aes_nonce)}
CAMELLIA_NONCE = {repr(self.camellia_nonce)}
CHACHA_NONCE = {repr(self.chacha_nonce)}
HIDDEN = "{hidden_code}"
CHUNK_SIZE = {self.chunk_size}

def _k():
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),length=32,salt=SALT,iterations=150000)
    return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key_v6"))
cipher = Fernet(_k())

def _xor(d):
    return bytes(a ^ b for a, b in zip(d, XOR_KEY * (len(d) // len(XOR_KEY) + 1)))

def _aes(d, decrypt=True):
    try:
        c = Cipher(algorithms.AES(AES_KEY), modes.CTR(AES_NONCE))
        if decrypt:
            dec = c.decryptor()
            return dec.update(d) + dec.finalize()
        else:
            enc = c.encryptor()
            return enc.update(d) + enc.finalize()
    except Exception as e:
        raise Exception(f"AES decoding hatası: {{str(e)}}")

def _camellia(d, decrypt=True):
    try:
        c = Cipher(algorithms.Camellia(CAMELLIA_KEY), modes.CTR(CAMELLIA_NONCE))
        if decrypt:
            dec = c.decryptor()
            return dec.update(d) + dec.finalize()
        else:
            enc = c.encryptor()
            return enc.update(d) + enc.finalize()
    except Exception as e:
        raise Exception(f"Camellia decoding hatası: {{str(e)}}")

def _chacha(d, decrypt=True):
    try:
        chacha = ChaCha20Poly1305(CHACHA_KEY)
        if decrypt:
            return chacha.decrypt(CHACHA_NONCE, d, None)
        else:
            return chacha.encrypt(CHACHA_NONCE, d, None)
    except Exception as e:
        raise Exception(f"ChaCha decoding hatası: {{str(e)}}")

def _hash(d):
    md5 = hashes.Hash(hashes.MD5())
    md5.update(d)
    h1 = md5.finalize()
    sha256 = hashes.Hash(hashes.SHA256())
    sha256.update(h1)
    h2 = sha256.finalize()
    sha512 = hashes.Hash(hashes.SHA512())
    sha512.update(h2)
    return sha512.finalize()

def _hmac(d):
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256())
    h.update(d)
    return h.finalize()

def _scramble(d):
    mid = len(d) // 2
    random.seed(binascii.hexlify(SALT))
    parts = [d[:mid], d[mid:]]
    random.shuffle(parts)
    return b''.join(parts)

def _chunk(d, decrypt=True):
    chunks = [d[i:i + CHUNK_SIZE] for i in range(0, len(d), CHUNK_SIZE)]
    return b''.join(base64.b85decode(chunk) if decrypt else base64.b85encode(chunk) for chunk in chunks)

def _d(data):
    try:
        x = base64.b64decode(data)
        x = _chunk(x, decrypt=True)
        x = binascii.unhexlify(x)
        fernet_encrypted, hash_tag, hmac_tag = x[:-96], x[-96:-32], x[-32:]
        if _hmac(fernet_encrypted + hash_tag) != hmac_tag:
            raise ValueError("HMAC doğrulaması başarısız!")
        if _hash(fernet_encrypted) != hash_tag:
            raise ValueError("Hash doğrulaması başarısız!")
        x = cipher.decrypt(fernet_encrypted)
        x = _xor(x)
        x = _aes(x, decrypt=True)
        x = _camellia(x, decrypt=True)
        x = _scramble(x)
        x = zlib.decompress(x)
        x = _chacha(x, decrypt=True)
        return x.decode('utf-8')  # Baytları string'e çevir
    except Exception as e:
        raise Exception(f"Decoding error: {{str(e)}}")

def _{random.randint(1000, 9999)}(x): return x * {random.randint(1, 20)}
def _{random.randint(1000, 9999)}(y): return y // {random.randint(2, 10)}
{random.randint(100000, 999999)}

try:
    decoded = _d(HIDDEN)
    exec(decoded)  # Direkt string olarak çalıştır
except Exception as e:
    sys.exit(f"Çalıştırma hatası: {{str(e)}}")
"""
            temp_file = "temp_conf_v6.py"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)

            pyc_file = output_file.replace('.py', '.pyc')
            py_compile.compile(temp_file, cfile=pyc_file, optimize=2, doraise=True)
            os.remove(temp_file)
            print(f"Ultra güçlü 12 katmanlı obfuscated dosya: {pyc_file}")

        except Exception as e:
            print(f"Hata: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python encryptor.py <dosya.py>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file.replace('.py', '_v6.py')
    obf = UltraObfuscatorConf()
    obf.create_hidden_script(input_file, output_file)

if __name__ == "__main__":
    main()
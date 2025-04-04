import sys
import os
import py_compile
import marshal
import base64
import zlib
import random
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
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
        self.noise = ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=15))
        self.xor_key = os.urandom(32)
        self.aes_key = os.urandom(32)
        self.chacha_key = os.urandom(32)  # ChaCha20 için 256-bit anahtar
        self.nonce = os.urandom(16)       # AES için nonce
        self.chacha_nonce = os.urandom(12) # ChaCha20 için 96-bit nonce
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
        self.chunk_size = 100000  # Veri parçalama boyutu

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=self.salt,
            iterations=50000,
        )
        return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key_v3"))

    def _xor_layer(self, data):
        if not isinstance(data, bytes):
            raise ValueError("XOR layer: Input must be bytes")
        return bytes(a ^ b for a, b in zip(data, self.xor_key * (len(data) // len(self.xor_key) + 1)))

    def _aes_layer(self, data, encrypt=True):
        if not isinstance(data, bytes):
            raise ValueError("AES layer: Input must be bytes")
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(self.nonce))
        if encrypt:
            encryptor = cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()
        else:
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()

    def _chacha_layer(self, data, encrypt=True):
        if not isinstance(data, bytes):
            raise ValueError("ChaCha layer: Input must be bytes")
        chacha = ChaCha20Poly1305(self.chacha_key)
        if encrypt:
            return chacha.encrypt(self.chacha_nonce, data, None)
        else:
            return chacha.decrypt(self.chacha_nonce, data, None)

    def _chunk_data(self, data, encrypt=True):
        if not isinstance(data, bytes):
            raise ValueError("Chunk data: Input must be bytes")
        chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
        if encrypt:
            return b''.join(base64.b85encode(chunk) for chunk in chunks)
        else:
            return b''.join(base64.b85decode(chunk) for chunk in chunks)

    def hide_code(self, code):
        try:
            if not isinstance(code, str):
                raise ValueError("Hide code: Code must be a string")
            compiled = compile(code, '<hidden>', 'exec')
            marshaled = marshal.dumps(compiled)
            compressed = zlib.compress(marshaled, level=9)
            aes_encrypted = self._aes_layer(compressed, encrypt=True)
            xor_obfuscated = self._xor_layer(aes_encrypted)
            fernet_encrypted = self.cipher.encrypt(xor_obfuscated)
            chacha_encrypted = self._chacha_layer(fernet_encrypted, encrypt=True)
            hexed = binascii.hexlify(chacha_encrypted)
            b85_chunks = self._chunk_data(hexed, encrypt=True)
            encoded = base64.b64encode(b85_chunks).decode('utf-8')
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
import marshal
import base64
import zlib
import random
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

{random.randint(10000, 99999)}
SALT = {repr(self.salt)}
NOISE = "{self.noise}"
XOR_KEY = {repr(self.xor_key)}
AES_KEY = {repr(self.aes_key)}
CHACHA_KEY = {repr(self.chacha_key)}
NONCE = {repr(self.nonce)}
CHACHA_NONCE = {repr(self.chacha_nonce)}
HIDDEN = "{hidden_code}"
CHUNK_SIZE = {self.chunk_size}

def _k():
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),length=32,salt=SALT,iterations=50000)
    return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key_v3"))
cipher = Fernet(_k())

def _xor(d):
    if not isinstance(d, bytes):
        raise ValueError("XOR: Input must be bytes")
    return bytes(a ^ b for a, b in zip(d, XOR_KEY * (len(d) // len(XOR_KEY) + 1)))

def _aes(d, decrypt=True):
    if not isinstance(d, bytes):
        raise ValueError("AES: Input must be bytes")
    c = Cipher(algorithms.AES(AES_KEY), modes.CTR(NONCE))
    if decrypt:
        dec = c.decryptor()
        return dec.update(d) + dec.finalize()
    else:
        enc = c.encryptor()
        return enc.update(d) + enc.finalize()

def _chacha(d, decrypt=True):
    if not isinstance(d, bytes):
        raise ValueError("ChaCha: Input must be bytes")
    chacha = ChaCha20Poly1305(CHACHA_KEY)
    if decrypt:
        return chacha.decrypt(CHACHA_NONCE, d, None)
    else:
        return chacha.encrypt(CHACHA_NONCE, d, None)

def _chunk(d, decrypt=True):
    if not isinstance(d, bytes):
        raise ValueError("Chunk: Input must be bytes")
    chunks = [d[i:i + CHUNK_SIZE] for i in range(0, len(d), CHUNK_SIZE)]
    return b''.join(base64.b85decode(chunk) if decrypt else base64.b85encode(chunk) for chunk in chunks)

def _d(data):
    try:
        if not isinstance(data, str):
            raise ValueError("Decode: Input must be a string")
        x = base64.b64decode(data)
        x = _chunk(x, decrypt=True)
        x = binascii.unhexlify(x)
        x = _chacha(x, decrypt=True)
        x = cipher.decrypt(x)
        x = _xor(x)
        x = _aes(x, decrypt=True)
        x = zlib.decompress(x)
        return x
    except Exception as e:
        raise Exception(f"Decoding error: {{str(e)}}")

def _{random.randint(1000, 9999)}(x): return x * {random.randint(1, 15)}
{random.randint(10000, 99999)}

try:
    decoded = _d(HIDDEN)
    bytecode = marshal.loads(decoded)
    exec(bytecode)
except Exception as e:
    sys.exit(f"Çalıştırma hatası: {{str(e)}}")
"""
            temp_file = "temp_conf_v3.py"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)

            pyc_file = output_file.replace('.py', '.pyc')
            py_compile.compile(temp_file, cfile=pyc_file, optimize=2, doraise=True)
            os.remove(temp_file)
            print(f"Ultra güçlü obfuscated dosya: {pyc_file}")

        except Exception as e:
            print(f"Hata: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python encryptor.py <dosya.py>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file.replace('.py', '_v3.py')
    obf = UltraObfuscatorConf()
    obf.create_hidden_script(input_file, output_file)

if __name__ == "__main__":
    main()
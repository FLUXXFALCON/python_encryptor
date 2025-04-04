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

try:
    from cryptography import fernet
except ImportError:
    print("Hata: 'cryptography' gerekli. Kur: pip install cryptography")
    sys.exit(1)

class UltraObfuscatorConf:
    def __init__(self):
        self.salt = os.urandom(16)
        self.noise = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=20000,
        )
        return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key"))

    def hide_code(self, code):
        try:
            compiled = compile(code, '<hidden>', 'exec')
            marshaled = marshal.dumps(compiled)
            compressed = zlib.compress(marshaled)
            encrypted = self.cipher.encrypt(compressed)
            hexed = binascii.hexlify(encrypted)
            b85 = base64.b85encode(hexed)
            encoded = base64.b64encode(b85).decode('utf-8')
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
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

{random.randint(1000, 9999)}
SALT = {repr(self.salt)}
NOISE = "{self.noise}"
HIDDEN = "{hidden_code}"

def _k():
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=SALT,iterations=20000)
    return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key"))
cipher = Fernet(_k())

def _d(data):
    x = base64.b64decode(data)
    x = base64.b85decode(x)
    x = binascii.unhexlify(x)
    x = cipher.decrypt(x)
    x = zlib.decompress(x)
    return x

def _{random.randint(100, 999)}(x): return x * {random.randint(1, 10)}
{random.randint(1000, 9999)}

try:
    decoded = base64.b64decode(HIDDEN)
    b85 = base64.b85decode(decoded)
    unhexed = binascii.unhexlify(b85)
    decrypted = cipher.decrypt(unhexed)
    decompressed = zlib.decompress(decrypted)
    bytecode = marshal.loads(decompressed)
    exec(bytecode)
except Exception as e:
    sys.exit(f"Çalıştırma hatası: {{str(e)}}")
"""
            temp_file = "temp_conf.py"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)

            pyc_file = output_file.replace('.py', '_conf.pyc')
            py_compile.compile(temp_file, cfile=pyc_file, optimize=1, doraise=True)
            os.remove(temp_file)
            print(f"Confusion obfuscated dosya: {pyc_file}")

        except Exception as e:
            print(f"Hata: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python grok_conf.py <dosya.py>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file.replace('.py', '_conf.py')
    obf = UltraObfuscatorConf()
    obf.create_hidden_script(input_file, output_file)

if __name__ == "__main__":
    main()
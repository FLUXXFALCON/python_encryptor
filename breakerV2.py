import sys
import marshal
import base64
import binascii
import zlib
import subprocess
import struct
import os
import time
import random
from typing import Optional, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class UltraPycCracker:
    MAGIC_NUMBERS = {
        (3, 11): b'\xa7\x0d\x0d\x0a',
        (3, 10): b'\x55\x0d\x0d\x0a',
        (3, 9): b'\x42\x0d\x0d\x0a',
    }

    def __init__(self, input_file: str):
        self.input_file = input_file
        self.output_pyc = self.input_file.replace('.pyc', '_cracked.pyc') or 'cracked_output.pyc'
        self.output_py = self.input_file.replace('.pyc', '_decompiled.py') or 'decompiled_output.py'
        self.python_version = self._detect_python_version()
        self.attempted_methods: List[str] = []
        self.chunk_size = 50000
        self.namespace = {}

    def _detect_python_version(self) -> tuple:
        with open(self.input_file, 'rb') as f:
            magic = f.read(4)
            for version, magic_num in self.MAGIC_NUMBERS.items():
                if magic == magic_num:
                    return version
        print("Uyarı: Python sürümü tespit edilemedi, 3.11 varsayıldı")
        return (3, 11)

    def _is_valid_bytecode(self, data: bytes) -> bool:
        try:
            code_obj = marshal.loads(data)
            return hasattr(code_obj, 'co_code')
        except:
            return False

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=150000,
        )
        return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key_v6"))

    def _base64_decode(self, data: bytes) -> Optional[bytes]:
        try:
            return base64.b64decode(data)
        except Exception as e:
            print(f"Base64 decode hatası: {e}")
            return None

    def _base85_decode(self, data: bytes) -> Optional[bytes]:
        try:
            return base64.b85decode(data)
        except Exception as e:
            print(f"Base85 decode hatası: {e}")
            return None

    def _hex_decode(self, data: bytes) -> Optional[bytes]:
        try:
            return binascii.unhexlify(data)
        except Exception as e:
            print(f"Hex decode hatası: {e}")
            return None

    def _fernet_decode(self, data: bytes, salt: bytes) -> Optional[bytes]:
        try:
            cipher = Fernet(self._derive_key(salt))
            return cipher.decrypt(data)
        except Exception as e:
            print(f"Fernet decode hatası: {e}")
            return None

    def _xor_decode(self, data: bytes, xor_key: bytes) -> Optional[bytes]:
        try:
            return bytes(a ^ b for a, b in zip(data, xor_key * (len(data) // len(xor_key) + 1)))
        except Exception as e:
            print(f"XOR decode hatası: {e}")
            return None

    def _aes_decode(self, data: bytes, aes_key: bytes, aes_nonce: bytes) -> Optional[bytes]:
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_nonce))
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            print(f"AES decode hatası: {e}")
            return None

    def _camellia_decode(self, data: bytes, camellia_key: bytes, camellia_nonce: bytes) -> Optional[bytes]:
        try:
            cipher = Cipher(algorithms.Camellia(camellia_key), modes.CTR(camellia_nonce))
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        except Exception as e:
            print(f"Camellia decode hatası: {e}")
            return None

    def _chacha_decode(self, data: bytes, chacha_key: bytes, chacha_nonce: bytes) -> Optional[bytes]:
        try:
            chacha = ChaCha20Poly1305(chacha_key)
            return chacha.decrypt(chacha_nonce, data, None)
        except Exception as e:
            print(f"ChaCha decode hatası: {e}")
            return None

    def _zlib_decode(self, data: bytes) -> Optional[bytes]:
        try:
            return zlib.decompress(data)
        except Exception as e:
            print(f"Zlib decode hatası: {e}")
            return None

    def _scramble_decode(self, data: bytes, salt: bytes) -> Optional[bytes]:
        try:
            mid = len(data) // 2
            random.seed(binascii.hexlify(salt))
            parts = [data[:mid], data[mid:]]
            random.shuffle(parts)
            return parts[1] + parts[0] if random.randint(0, 1) == 0 else parts[0] + parts[1]
        except Exception as e:
            print(f"Scramble decode hatası: {e}")
            return None

    def _chunk_decode(self, data: bytes) -> Optional[bytes]:
        try:
            chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            return b''.join(base64.b85decode(chunk) for chunk in chunks)
        except Exception as e:
            print(f"Chunk decode hatası: {e}")
            return None

    def _marshal_decode(self, data: bytes) -> Optional[bytes]:
        try:
            code_obj = marshal.loads(data)
            if hasattr(code_obj, 'co_code'):
                return data  # Marshal edilmiş veri zaten bytecode, direkt döndür
            return None
        except Exception as e:
            print(f"Marshal decode hatası: {e}")
            return None

    def _hmac_verify(self, data: bytes, hmac_key: bytes, hmac_tag: bytes) -> bool:
        try:
            h = hmac.HMAC(hmac_key, hashes.SHA256())
            h.update(data)
            return h.finalize() == hmac_tag
        except Exception as e:
            print(f"HMAC verify hatası: {e}")
            return False

    def _hash_verify(self, data: bytes, hash_tag: bytes) -> bool:
        try:
            md5 = hashes.Hash(hashes.MD5())
            md5.update(data)
            h1 = md5.finalize()
            sha256 = hashes.Hash(hashes.SHA256())
            sha256.update(h1)
            h2 = sha256.finalize()
            sha512 = hashes.Hash(hashes.SHA512())
            sha512.update(h2)
            return sha512.finalize() == hash_tag
        except Exception as e:
            print(f"Hash verify hatası: {e}")
            return False

    def crack_layers(self, data: any) -> Optional[bytes]:
        # Namespace'den anahtarları al
        salt = self.namespace.get('SALT', b'')
        xor_key = self.namespace.get('XOR_KEY', b'')
        aes_key = self.namespace.get('AES_KEY', b'')
        camellia_key = self.namespace.get('CAMELLIA_KEY', b'')
        chacha_key = self.namespace.get('CHACHA_KEY', b'')
        hmac_key = self.namespace.get('HMAC_KEY', b'')
        aes_nonce = self.namespace.get('AES_NONCE', b'')
        camellia_nonce = self.namespace.get('CAMELLIA_NONCE', b'')
        chacha_nonce = self.namespace.get('CHACHA_NONCE', b'')
        self.chunk_size = self.namespace.get('CHUNK_SIZE', 50000)

        current_data = data.encode('utf-8') if isinstance(data, str) else data
        self.attempted_methods = []

        steps = [
            ('base64', self._base64_decode),
            ('chunk', self._chunk_decode),
            ('hex', self._hex_decode),
            ('fernet', lambda x: self._fernet_decode(x, salt)),
            ('xor', lambda x: self._xor_decode(x, xor_key)),
            ('aes', lambda x: self._aes_decode(x, aes_key, aes_nonce)),
            ('camellia', lambda x: self._camellia_decode(x, camellia_key, camellia_nonce)),
            ('scramble', lambda x: self._scramble_decode(x, salt)),
            ('zlib', self._zlib_decode),
            ('chacha', lambda x: self._chacha_decode(x, chacha_key, chacha_nonce)),
            ('marshal', self._marshal_decode),  # Yeni eklenen marshal katmanı
        ]

        print(f"Başlangıç veri boyutu: {len(current_data)} bayt")
        for step_name, step_func in steps:
            if current_data:
                if step_name == 'hex' and len(current_data) > 96:
                    fernet_encrypted, hash_tag, hmac_tag = current_data[:-96], current_data[-96:-32], current_data[-32:]
                    hmac_valid = self._hmac_verify(fernet_encrypted + hash_tag, hmac_key, hmac_tag)
                    hash_valid = self._hash_verify(fernet_encrypted, hash_tag)
                    print(f"HMAC geçerli: {hmac_valid}, Hash geçerli: {hash_valid}")
                    if not (hmac_valid and hash_valid):
                        print("HMAC veya Hash doğrulaması başarısız, ancak devam ediliyor.")
                    current_data = fernet_encrypted
                    self.attempted_methods.append("hmac")
                    self.attempted_methods.append("hash")

                next_data = step_func(current_data)
                if next_data:
                    self.attempted_methods.append(step_name)
                    print(f"{step_name} başarılı, yeni veri boyutu: {len(next_data)} bayt")
                    current_data = next_data
                else:
                    print(f"{step_name} başarısız, işlem durduruluyor.")
                    break
            else:
                print("Veri boş, işlem durduruluyor.")
                break

        if current_data and self._is_valid_bytecode(current_data):
            print(f"Geçerli bytecode bulundu! Yöntemler: {self.attempted_methods}")
            return current_data
        print("Geçerli bytecode bulunamadı.")
        return current_data  # Hatalı olsa bile son durumu döndür

    def decompile_bytecode(self, bytecode: bytes) -> bool:
        temp_pyc = "temp_cracked.pyc"
        with open(temp_pyc, 'wb') as f:
            magic = self.MAGIC_NUMBERS[self.python_version]
            timestamp = struct.pack('<I', int(time.time()))
            size = struct.pack('<I', 0)
            padding = b'\x00\x00\x00\x00'
            f.write(magic + timestamp + size + padding + bytecode)
        print(f"Ara bytecode dosyası '{temp_pyc}' oluşturuldu.")

        try:
            result = subprocess.run(
                ['pycdc', temp_pyc],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                with open(self.output_py, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                print(f"Kaynak kod '{self.output_py}' olarak kaydedildi (pycdc ile).")
                os.remove(temp_pyc)
                return True
            else:
                print(f"pycdc hatası: {result.stderr}")
        except FileNotFoundError:
            print("Hata: 'pycdc' bulunamadı. Lütfen pycdc'yi kurun: https://github.com/zrax/pycdc")

        try:
            result = subprocess.run(
                ['uncompyle6', temp_pyc],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                with open(self.output_py, 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                print(f"Kaynak kod '{self.output_py}' olarak kaydedildi (uncompyle6 ile).")
                os.remove(temp_pyc)
                return True
            else:
                print(f"uncompyle6 hatası: {result.stderr}")
        except FileNotFoundError:
            print("Hata: 'uncompyle6' bulunamadı. Lütfen kurun: pip install uncompyle6")

        os.remove(temp_pyc)
        return False

    def extract_and_save(self) -> bool:
        try:
            with open(self.input_file, 'rb') as f:
                header = f.read(16)
                print(f"Dosya header'ı: {header.hex()}")
                wrapper_code_obj = marshal.load(f)

            self.namespace = {}
            exec(wrapper_code_obj, self.namespace)

            possible_names = ['HIDDEN', 'hidden_data', 'data', 'secret', 'code', 'bytecode']
            hidden_data = None
            for name in possible_names:
                if name in self.namespace:
                    hidden_data = self.namespace[name]
                    print(f"'{name}' bulundu ve işleniyor.")
                    break

            if not hidden_data:
                print("Hata: Gizli veri bulunamadı, ham veri deneniyor...")
                with open(self.input_file, 'rb') as f:
                    f.read(16)
                    hidden_data = f.read()
                    print(f"Ham veri boyutu: {len(hidden_data)} bayt")

            cracked_data = self.crack_layers(hidden_data)
            if not cracked_data:
                print("Hata: Veri elde edilemedi")
                return False

            with open(self.output_pyc, 'wb') as f:
                magic = self.MAGIC_NUMBERS[self.python_version]
                timestamp = struct.pack('<I', int(time.time()))
                size = struct.pack('<I', 0)
                padding = b'\x00\x00\x00\x00'
                f.write(magic + timestamp + size + padding + cracked_data)
            print(f"Bytecode '{self.output_pyc}' olarak kaydedildi.")

            if self.decompile_bytecode(cracked_data):
                print(f"Decompile başarılı!")
            else:
                print(f"Decompile başarısız. Manuel deneme önerisi:")
                print(f"  pycdc {self.output_pyc} > {self.output_py}")
                print(f"  uncompyle6 {self.output_pyc} > {self.output_py}")

            print(f"Kullanılan yöntemler: {self.attempted_methods}")
            return True

        except Exception as e:
            print(f"Kırma başarısız: {e}")
            return False

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python breaker.py <gizlenmis_dosya.pyc>")
        sys.exit(1)

    pyc_file = sys.argv[1]
    if not os.path.exists(pyc_file):
        print(f"Hata: '{pyc_file}' dosyası bulunamadı")
        sys.exit(1)

    cracker = UltraPycCracker(pyc_file)
    success = cracker.extract_and_save()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
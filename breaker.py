import sys
import marshal
import base64
import binascii
import zlib
import subprocess
import struct
import os
import time
from typing import Optional, List
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class PycCracker:
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
            marshal.loads(data)
            return True
        except:
            return False

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=20000,
        )
        return base64.urlsafe_b64encode(kdf.derive(b"ultra_obf_key"))

    def _try_specific_decryption(self, hidden_data: str, salt: bytes) -> Optional[bytes]:
        try:
            decoded = base64.b64decode(hidden_data)
            self.attempted_methods.append("base64")
            b85 = base64.b85decode(decoded)
            self.attempted_methods.append("base85")
            unhexed = binascii.unhexlify(b85)
            self.attempted_methods.append("hex")
            cipher = Fernet(self._derive_key(salt))
            decrypted = cipher.decrypt(unhexed)
            self.attempted_methods.append("Fernet")
            decompressed = zlib.decompress(decrypted)
            self.attempted_methods.append("zlib")
            bytecode = marshal.loads(decompressed)
            self.attempted_methods.append("marshal")
            return decompressed
        except Exception as e:
            print(f"Spesifik çözümleme hatası: {e}")
            return None

    def _try_decode_methods(self, data: any) -> Optional[bytes]:
        methods = [
            ('base64', lambda x: base64.b64decode(x)),
            ('base85', lambda x: base64.b85decode(x)),
            ('hex', lambda x: binascii.unhexlify(x)),
            ('zlib', lambda x: zlib.decompress(x)),
            ('raw_bytes', lambda x: x.encode() if isinstance(x, str) else x),
        ]
        for method_name, decode_func in methods:
            try:
                if isinstance(data, (str, bytes)):
                    result = decode_func(data)
                    if isinstance(result, bytes) and len(result) > 0:
                        print(f"Başarılı yöntem: {method_name}")
                        self.attempted_methods.append(method_name)
                        return result
            except Exception:
                continue
        return None

    def crack_layers(self, data: any, salt: bytes = None) -> Optional[bytes]:
        current_data = data
        max_attempts = 50
        attempt = 0

        if salt and isinstance(data, str):
            result = self._try_specific_decryption(data, salt)
            if result and self._is_valid_bytecode(result):
                print(f"Geçerli bytecode bulundu! Yöntemler: {self.attempted_methods}")
                return result

        while attempt < max_attempts:
            if isinstance(current_data, bytes) and self._is_valid_bytecode(current_data):
                print(f"Geçerli bytecode bulundu! Yöntemler: {self.attempted_methods}")
                return current_data

            next_data = self._try_decode_methods(current_data)
            if next_data is None:
                print(f"Kalan veri: {current_data[:50].hex()}... (decode edilemedi)")
                break
            
            if next_data == current_data:
                break
            
            current_data = next_data
            attempt += 1

        return current_data if isinstance(current_data, bytes) else None

    def decompile_bytecode(self, bytecode: bytes) -> bool:
        temp_pyc = "temp_cracked.pyc"
        with open(temp_pyc, 'wb') as f:
            magic = self.MAGIC_NUMBERS[self.python_version]
            timestamp = struct.pack('<I', int(time.time()))
            size = struct.pack('<I', 0)
            padding = b'\x00\x00\x00\x00'
            f.write(magic + timestamp + size + padding)
            marshal.dump(marshal.loads(bytecode), f)
        print(f"Ara bytecode dosyası '{temp_pyc}' oluşturuldu.")

        # pycdc ile decompile
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
            return False

        os.remove(temp_pyc)
        return False

    def extract_and_save(self) -> bool:
        try:
            with open(self.input_file, 'rb') as f:
                header = f.read(16)
                print(f"Dosya header'ı: {header.hex()}")
                wrapper_code_obj = marshal.load(f)

            namespace = {}
            exec(wrapper_code_obj, namespace)

            possible_names = ['HIDDEN', 'hidden_data', 'data', 'secret', 'code', 'bytecode']
            hidden_data = None
            for name in possible_names:
                if name in namespace:
                    hidden_data = namespace[name]
                    print(f"'{name}' bulundu ve işleniyor.")
                    break

            salt = namespace.get('SALT')
            if not hidden_data:
                print("Hata: Gizli veri bulunamadı, ham veri deneniyor...")
                with open(self.input_file, 'rb') as f:
                    f.read(16)
                    hidden_data = f.read()
                    print(f"Ham veri boyutu: {len(hidden_data)} bayt")

            cracked_data = self.crack_layers(hidden_data, salt)
            if not cracked_data or not self._is_valid_bytecode(cracked_data):
                print("Hata: Geçerli bytecode elde edilemedi")
                return False

            with open(self.output_pyc, 'wb') as f:
                magic = self.MAGIC_NUMBERS[self.python_version]
                timestamp = struct.pack('<I', int(time.time()))
                size = struct.pack('<I', 0)
                padding = b'\x00\x00\x00\x00'
                f.write(magic + timestamp + size + padding)
                marshal.dump(marshal.loads(cracked_data), f)
            print(f"Bytecode '{self.output_pyc}' olarak kaydedildi.")

            if self.decompile_bytecode(cracked_data):
                print(f"Decompile başarılı!")
            else:
                print(f"Decompile başarısız. Manuel deneme önerisi:")
                print(f"  pycdc {self.output_pyc} > {self.output_py}")

            print(f"Kullanılan yöntemler: {self.attempted_methods}")
            return True

        except Exception as e:
            print(f"Kırma başarısız: {e}")
            return False

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python break.py <gizlenmis_dosya.pyc>")
        sys.exit(1)

    pyc_file = sys.argv[1]
    if not os.path.exists(pyc_file):
        print(f"Hata: '{pyc_file}' dosyası bulunamadı")
        sys.exit(1)

    cracker = PycCracker(pyc_file)
    success = cracker.extract_and_save()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
---

# Ultra Obfuscator

Ultra Obfuscator, Python betiklerini şifreleyerek, sıkıştırarak ve kodu gizleyerek koruma sağlayan bir araçtır. Bu araç, Python kodunun kaynaklarını obfuscate ederek, başkalarının orijinal kodu anlamasını zorlaştırır. Genellikle yazılım güvenliği ve fikri mülkiyetin korunması amacıyla kullanılır.

## Özellikler

- Python betiklerini şifreler, sıkıştırır ve kodu gizler.
- Şifreleme için **Fernet** algoritmasını kullanır.
- Python bytecode'larını gizler ve yeniden çalıştırılabilir hale getirir.
- Base64, Base85 ve Hex gibi çeşitli encoding teknikleriyle şifreleme sağlar.
- PBKDF2-HMAC algoritması ile anahtar türetme işlemi yapılır.

## Kullanım

### Gereksinimler

Ultra Obfuscator, **cryptography** kütüphanesine ihtiyaç duyar. Aşağıdaki komutla bu kütüphaneyi kurabilirsiniz:

```bash
pip install cryptography
```

### Adım Adım Kullanım

1. **UltraObfuscator** sınıfını kullanarak bir Python dosyasını obfuscate edebilirsiniz.
2. `encryptor.py` betiğini çalıştırarak obfuscation işlemini gerçekleştirebilirsiniz.

#### Komut Satırı Kullanımı

Obfuscation işlemini şu şekilde başlatabilirsiniz:

```bash
python encryptor.py <dosya_adı.py>
```

Örneğin:

```bash
python encryptor.py example.py
```

Bu komut, `example.py` dosyasını alır ve obfuscate ederek `example_conf.pyc` adlı bir dosya oluşturur.

### Kodun Yapısı

- **UltraObfuscatorConf** sınıfı, şifreleme anahtarlarını türetir ve Python kodunu obfuscate eder.
- **hide_code()** metodu, verilen Python kodunu derler, marshal (bytecode’a dönüştürme), sıkıştırır, şifreler ve ardından kodu base64 ve base85 gibi formatlarla kodlar.
- **create_hidden_script()** metodu, bir Python dosyasını okuyarak obfuscate eder ve bir wrapper script oluşturur.

## Kütüphaneler

Bu projede kullanılan başlıca kütüphaneler:

- **cryptography**: Şifreleme işlemleri için kullanılır. `Fernet` şifreleme ve `PBKDF2-HMAC` anahtar türetme algoritması bu kütüphanede bulunmaktadır.
- **zlib**: Verilerin sıkıştırılması ve açılması için kullanılır.
- **base64**: Verilerin base64 formatına kodlanması için kullanılır.
- **binascii**: Hex kodlarının dönüştürülmesinde kullanılır.
- **marshal**: Python bytecode’larını işlemek için kullanılır.

---

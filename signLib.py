from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64

def str_to_pubkey(key_str):
    return serialization.load_pem_public_key(base64.b85decode(key_str.encode('utf-8')), backend=default_backend())

def str_to_prikey(key_str):
    return serialization.load_pem_private_key(base64.b85decode(key_str.encode('utf-8')), backend=default_backend(), password=None)

def pubkey_to_str(pubkey, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return base64.b85encode(pubkey.public_bytes(encoding=encoding, format=format)).decode('utf-8')

def prikey_to_str(prikey, encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8):
    return base64.b85encode(prikey.private_bytes(encoding=encoding, format=format, encryption_algorithm=serialization.NoEncryption())).decode('utf-8')

def sign(private_key, data, hash_method=hashes.SHA256, padding_method='PSS'):
    if padding_method == 'PSS':
        padding_mth = padding.PSS(
        mgf=padding.MGF1(hash_method()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    elif padding_method == 'PKCS1v15':
        padding_mth = padding.PKCS1v15()
    else:
        raise ArgumentError("padding_method must be 'PSS' or 'PKCS1v15'")
    return base64.b85encode(str_to_prikey(private_key).sign(
        data,
        padding_mth,
        hash_method()
    )).decode('utf-8') + ' ' + base64.b85encode(data).decode('utf-8')

def verify(public_key, signatured_data, hash_method=hashes.SHA256, padding_method='PSS'):
    signature, data = signatured_data.split(' ')
    try:
        if padding_method == 'PSS':
            padding_mth = padding.PSS(
                mgf=padding.MGF1(hash_method()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        elif padding_method == 'PKCS1v15':
            padding_mth = padding.PKCS1v15()
        else:
            raise ArgumentError("padding_method must be 'PSS' or 'PKCS1v15'")
        str_to_pubkey(public_key).verify(
            base64.b85decode(signature.encode('utf-8')),
            base64.b85decode(data.encode('utf-8')),
            padding_mth,
            hash_method()
        )
        return (True, data)
    except Exception as e:
        return False

class ArgumentError(Exception):
    def __init__(self, message):
        super().__init__(message)

class MissingKeyError(ArgumentError):
    def __init__(self, message):
        super().__init__(message)

class LotKeyError(ArgumentError):
    def __init__(self, message):
        super().__init__(message)

class NotLoadedKeyError(MissingKeyError):
    def __init__(self, message):
        super().__init__(message)

class Signer:
    __doc__ = """\
签名器类，用于签名和验证数据。
Signer(数据[必须提供], 公钥链[可选], 信任的根公钥[可选], 私钥[可选])
(当然了 你可以直接更改类中的属性 毕竟类没有提供修改属性的方法)
trused_root_key str: 信任的根公钥，当自己不是根公钥时必须提供
key_line list: [根公钥签名的公钥1, 公钥1签名的公钥2, 公钥2签名的公钥3, ..., 自己上级公钥签名的自己的公钥]
注意: 在类中实际存储的公钥链是传入的公钥链反过来的 所以你在直接更改时需要注意
private_key str: 自己的私钥
public_key str: 自己的公钥
sha_method str: 签名使用的哈希算法, 默认为SHA256"""
    def __init__(self, data: bytes, key_line: list=[], trused_root_key: str=None, private_key: str=None, public_key: str=None, padding_method: str='PSS', hash_method: hashes=hashes.SHA256):
        if len(key_line) == 0:
            raise MissingKeyError("请至少提供自己的公钥!")
        elif len(key_line) == 1 and trused_root_key is not None:
            raise LotKeyError("请不要提供信任的根公钥!(当自己是根公钥时)")
        elif len(key_line) > 1 and trused_root_key is None:
            raise MissingKeyError("请提供信任的根公钥!(当自己不是根公钥时)")
        self.trused_root_key = trused_root_key
        self.key_line = list(key_line)
        self.private_key = private_key
        self.public_key = public_key
        self.data = data
        self.padding_method = padding_method
        self.hash_method = hash_method
    def sign_data(self):
        if not self.private_key:
            raise NotLoadedKeyError("请先加载私钥!")
        return sign(self.private_key, self.data, self.hash_method, self.padding_method)
    def verify_data(self, signatured_data):
        if not self.public_key:
            raise NotLoadedKeyError("请先加载公钥!")
        return verify(self.public_key, signatured_data, self.hash_method, self.padding_method)
    def verify_key_line(self):
        if len(self.key_line) == 0:
            raise MissingKeyError("请至少提供自己的公钥!")
        if self.trused_root_key is None:
            return True
        last_trused_key = self.trused_root_key
        for i in range(len(self.key_line)):
            if i == 0:
                if self.key_line[i] != self.trused_root_key:
                    return False
                continue
            this = self.key_line[i].split('\t')
            signatured_pub_key = this[1]
            if not verify(last_trused_key, signatured_pub_key, self.hash_method, self.padding_method):
                return False
            last_trused_key = this[0]
        return True
    def export_key_line(self):
        return list(self.key_line)
    def export_private_key(self):
        return self.private_key
    def export_public_key(self):
        return self.public_key

# -------------测试代码--------------

# 生成3对公钥和私钥
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key2 = private_key2.public_key()

private_key3 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key3 = private_key3.public_key()

attacker_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

attacker_public_key = attacker_private_key.public_key()

# 公钥链
key_line = [
    pubkey_to_str(public_key), 
    pubkey_to_str(public_key2) + '\t' +  sign(prikey_to_str(private_key), pubkey_to_str(public_key2).encode('utf-8')), 
    pubkey_to_str(public_key3) + '\t' +  sign(prikey_to_str(private_key2), pubkey_to_str(public_key3).encode('utf-8'))
]

# 信任的根公钥
trused_root_key = pubkey_to_str(public_key)

# 要签名的数据
data = "这是一个需要被签名的消息。".encode("utf-8")

# 签名实例化
signer = Signer(data, key_line=key_line, trused_root_key=trused_root_key, private_key=prikey_to_str(private_key3), public_key=pubkey_to_str(public_key3))
print(signer.verify_data(signer.sign_data()))
print(signer.verify_key_line())

# 模拟公钥链被攻击

key_line[0] = pubkey_to_str(attacker_public_key)

signer.key_line = key_line

print(signer.verify_key_line())

key_line[0] = pubkey_to_str(public_key)
key_line[1] = pubkey_to_str(attacker_public_key) + '\t' +  sign(prikey_to_str(private_key), pubkey_to_str(attacker_public_key).encode('utf-8'))

signer.key_line = key_line

print(signer.verify_key_line())

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64

__doc__ = """\
这是一个签名库 
函数功能:
str_to_pubkey(key_str) -> object: 将公钥字符串转换为公钥对象
str_to_prikey(key_str) -> object: 将私钥字符串转换为私钥对象
pubkey_to_str(pubkey, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) -> str: 将公钥对象转换为公钥字符串
prikey_to_str(prikey, encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8) -> str: 将私钥对象转换为私钥字符串
auto_prikey_to_str(prikey, encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8) -> str: 自动判断私钥对象或私钥字符串并转换为私钥字符串
auto_pubkey_to_str(pubkey, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) -> str: 自动判断公钥对象或公钥字符串并转换为公钥字符串
auto_str_to_prikey(key_str) -> object: 自动判断私钥字符串或私钥对象并转换为私钥对象
auto_str_to_pubkey(key_str) -> object: 自动判断公钥字符串或公钥对象并转换为公钥对象
sign(private_key: object, data: bytes, hash_method=hashes.SHA256, padding_method='PSS') -> str: 签名函数 输出为b85编码的签名字符串+b85编码的数据字符串
verify(public_key: object, signatured_data: str, hash_method=hashes.SHA256, padding_method='PSS') -> tuple/bool: 验证签名函数 输入为b85编码的签名字符串+b85编码的数据字符串 当验证成功时返回True和数据字符串 否则返回False
verify_key_line(key_line: list, trused_root_key: str='', hash_method=hashes.SHA256, padding_method='PSS') -> bool: 验证公钥链函数 输入为公钥链列表 输出为True/False
gen_key_line(trused_root_key: str='', trused_root_key_pri: str='', keys: list=[], hash_method=hashes.SHA256, padding_method='PSS') -> list: 生成公钥链函数 输入为信任根公钥字符串、信任根私钥字符串、密钥列表[(公钥, 私钥)...]、哈希方法、填充方法 输出为公钥链列表
dump_key_line(key_line) -> str: 将公钥链列表转换为字符串
load_key_line(key_line) -> list: 将字符串转换为公钥链列表
get_pubkey(key_line, index='last') -> str: 从公钥链获取公钥字符串
默认导入的模块:
cryptography.hazmat.primitives.hashes
cryptography.hazmat.primitives.serialization
cryptography.hazmat.primitives.asymmetric.padding
cryptography.hazmat.primitives.asymmetric.rsa
cryptography.hazmat.backends.default_backend
base64
新增的异常:
ArgumentError
MissingKeyError
LotKeyError
NotLoadedKeyError

"""

def str_to_pubkey(key_str):
    return serialization.load_pem_public_key(base64.b85decode(key_str.encode('utf-8')), backend=default_backend())

def str_to_prikey(key_str):
    return serialization.load_pem_private_key(base64.b85decode(key_str.encode('utf-8')), backend=default_backend(), password=None)

def pubkey_to_str(pubkey, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return base64.b85encode(pubkey.public_bytes(encoding=encoding, format=format)).decode('utf-8')

def prikey_to_str(prikey, encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8):
    return base64.b85encode(prikey.private_bytes(encoding=encoding, format=format, encryption_algorithm=serialization.NoEncryption())).decode('utf-8')

def auto_prikey_to_str(prikey, encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8):
    return prikey if isinstance(prikey, str) else prikey_to_str(prikey, encoding, format)

def auto_pubkey_to_str(pubkey, encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return pubkey if isinstance(pubkey, str) else pubkey_to_str(pubkey, encoding, format)

def auto_str_to_prikey(key_str):
    return key_str if isinstance(key_str, rsa.RSAPrivateKey) else str_to_prikey(key_str)

def auto_str_to_pubkey(key_str):
    return key_str if isinstance(key_str, rsa.RSAPublicKey) else str_to_pubkey(key_str)

def sign(private_key: object, data: bytes, hash_method=hashes.SHA256, padding_method='PSS'):
    if padding_method == 'PSS':
        padding_mth = padding.PSS(
        mgf=padding.MGF1(hash_method()),
            salt_length=padding.PSS.MAX_LENGTH
        )
    elif padding_method == 'PKCS1v15':
        padding_mth = padding.PKCS1v15()
    else:
        raise ArgumentError("padding_method must be 'PSS' or 'PKCS1v15'")
    return base64.b85encode(auto_str_to_prikey(private_key).sign(
        data,
        padding_mth,
        hash_method()
    )).decode('utf-8') + ' ' + base64.b85encode(data).decode('utf-8')

def verify(public_key: object, signatured_data: str, hash_method=hashes.SHA256, padding_method='PSS'):
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
        auto_str_to_pubkey(public_key).verify(
            base64.b85decode(signature.encode('utf-8')),
            base64.b85decode(data.encode('utf-8')),
            padding_mth,
            hash_method()
        )
        return (True, base64.b85decode(data.encode('utf-8')).decode('utf-8'))
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

def verify_key_line(key_line: list, trused_root_key: str='', hash_method: object=hashes.SHA256, padding_method: str='PSS'):
    if len(key_line) == 0:
        raise MissingKeyError("请至少提供自己的公钥!")
    if trused_root_key == '':
        raise NotLoadedKeyError("请先加载信任根公钥!")
    last_trused_key = trused_root_key
    for i in range(len(key_line)):
        if i == 0:
            if key_line[i] != trused_root_key:
                return False
            continue
        this = key_line[i].split('\t')
        signatured_pub_key = this[1]
        if not verify(last_trused_key, signatured_pub_key, hash_method, padding_method):
            return False
        last_trused_key = this[0]
    return True

def dump_key_line(key_line):
    return '\n'.join(key_line)

def load_key_line(key_line):
    return key_line.split('\n')

def get_pubkey(key_line, index: int='last'):
    if index == 'last':
        index = len(key_line) - 1
    if index >= len(key_line):
        raise IndexError("公钥索引越界!")
    return key_line[0] if index == 0 else key_line[index].split('\t')[0]

def gen_key_line(trused_root_key: str='', trused_root_key_pri: str='', keys: list=[], hash_method: object=hashes.SHA256, padding_method: str='PSS'):
    if len(keys) == 0 or trused_root_key == '':
        return
    temp = [trused_root_key]
    prikeys = [trused_root_key_pri] + [pri_key for pub_key, pri_key in keys]
    pubkeys = [trused_root_key] + [pub_key for pub_key, pri_key in keys]
    for i, keys in enumerate(keys):
        temp.append(auto_pubkey_to_str(pubkeys[0]) + '\t' + sign(prikeys[i], auto_pubkey_to_str(keys[0]), hash_method, padding_method))
    return temp

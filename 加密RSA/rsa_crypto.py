from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidKey
import base64
import logging

class RSACrypto:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_key_pair(self):
        """生成RSA密钥对"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # 获取私钥PEM格式
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # 获取公钥PEM格式
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem.decode(), public_pem.decode()
        except Exception as e:
            self.logger.error(f"生成密钥对时发生错误: {str(e)}")
            raise

    def encrypt(self, public_key_pem: str, plaintext: str) -> str:
        """使用公钥加密数据"""
        try:
            # 加载公钥
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # 加密数据
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 转换为base64格式
            return base64.b16encode(ciphertext).decode()
        except Exception as e:
            self.logger.error(f"加密过程中发生错误: {str(e)}")
            raise

    def decrypt(self, private_key_pem: str, ciphertext: str) -> str:
        """使用私钥解密数据"""
        try:
            # 加载私钥
            private_key = load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            
            # 解码密文
            try:
                encrypted_data = base64.b16decode(ciphertext.upper())
            except ValueError:
                raise ValueError("密文格式错误：请确保输入的是有效的16进制格式")
            
            # 解密数据
            plaintext = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext.decode()
        except InvalidKey:
            raise ValueError("私钥错误：无法使用提供的私钥进行解密")
        except Exception as e:
            self.logger.error(f"解密过程中发生错误: {str(e)}")
            raise 
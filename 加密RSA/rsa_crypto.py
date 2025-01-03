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
            # 验证输入
            if not public_key_pem.strip():
                raise ValueError("公钥不能为空")
            if not plaintext.strip():
                raise ValueError("明文不能为空")
            
            # 检查公钥格式
            if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
                raise ValueError("公钥格式错误：必须以'-----BEGIN PUBLIC KEY-----'开头")
            
            # 加载公钥
            try:
                public_key = serialization.load_pem_public_key(public_key_pem.encode())
            except ValueError as e:
                raise ValueError(f"公钥加载失败: {str(e)}")
            
            # 检查明文长度
            max_length = (public_key.key_size // 8) - 66  # OAEP padding overhead
            if len(plaintext.encode()) > max_length:
                raise ValueError(f"明文过长：最大允许{max_length}字节")
            
            # 加密数据
            try:
                ciphertext = public_key.encrypt(
                    plaintext.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                raise ValueError(f"加密失败: {str(e)}")
            
            # 转换为base64格式
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            self.logger.error(f"加密过程中发生错误: {str(e)}")
            raise ValueError(f"加密失败: {str(e)}")

    def decrypt(self, private_key_pem: str, ciphertext: str) -> str:
        """使用私钥解密数据"""
        try:
            # 验证输入
            if not private_key_pem.strip():
                raise ValueError("私钥不能为空")
            if not ciphertext.strip():
                raise ValueError("密文不能为空")
            
            # 检查私钥格式
            if not private_key_pem.startswith("-----BEGIN PRIVATE KEY-----"):
                raise ValueError("私钥格式错误：必须以'-----BEGIN PRIVATE KEY-----'开头")
            
            # 加载私钥
            try:
                private_key = load_pem_private_key(
                    private_key_pem.encode(),
                    password=None
                )
            except ValueError as e:
                raise ValueError(f"私钥加载失败: {str(e)}")
            
            # 解码密文
            try:
                encrypted_data = base64.b64decode(ciphertext)
            except ValueError:
                raise ValueError("密文格式错误：请确保输入的是有效的base64格式")
            
            # 解密数据
            try:
                plaintext = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                raise ValueError(f"解密失败: {str(e)}")
            
            return plaintext.decode()
        except Exception as e:
            self.logger.error(f"解密过程中发生错误: {str(e)}")
            raise ValueError(f"解密失败: {str(e)}")

    def save_to_file(self, content: str, filename: str):
        """保存内容到文件"""
        try:
            with open(filename, 'w') as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"保存文件失败: {str(e)}")
            raise

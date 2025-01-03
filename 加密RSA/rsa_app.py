from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

class RSAApp:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """生成2048位的RSA密钥对"""
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        print("密钥对已生成，请妥善保存私钥：")
        print(self.private_key.decode())
        print("\n公钥（可分享）：")
        print(self.public_key.decode())

    def encrypt(self, plaintext):
        """使用公钥加密数据"""
        if not self.public_key:
            raise ValueError("请先生成或导入公钥")
            
        rsa_key = RSA.import_key(self.public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted = cipher.encrypt(plaintext.encode())
        return binascii.hexlify(encrypted).decode()

    def decrypt(self, ciphertext, private_key=None):
        """使用私钥解密数据"""
        try:
            if private_key:
                key = RSA.import_key(private_key.encode())
            else:
                if not self.private_key:
                    raise ValueError("请提供私钥")
                key = RSA.import_key(self.private_key)
                
            cipher = PKCS1_OAEP.new(key)
            decrypted = cipher.decrypt(binascii.unhexlify(ciphertext))
            return decrypted.decode()
        except (ValueError, TypeError, binascii.Error) as e:
            raise ValueError("解密失败：密文格式错误或私钥不匹配") from e

if __name__ == "__main__":
    app = RSAApp()
    print("RSA加密解密程序")
    print("1. 生成密钥对")
    print("2. 加密")
    print("3. 解密")
    
    while True:
        choice = input("\n请选择操作（1/2/3）：")
        
        if choice == "1":
            app.generate_keys()
        elif choice == "2":
            plaintext = input("请输入要加密的文本：")
            try:
                ciphertext = app.encrypt(plaintext)
                print(f"加密结果：{ciphertext}")
            except Exception as e:
                print(f"加密失败：{str(e)}")
        elif choice == "3":
            ciphertext = input("请输入要解密的密文：")
            private_key = input("请输入私钥（留空使用生成的私钥）：")
            try:
                plaintext = app.decrypt(ciphertext, private_key)
                print(f"解密结果：{plaintext}")
            except Exception as e:
                print(f"解密失败：{str(e)}")
        else:
            print("无效选择")

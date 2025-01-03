from rsa_crypto import RSACrypto

def main():
    crypto = RSACrypto()
    
    try:
        # 生成密钥对
        print("正在生成RSA密钥对...")
        private_key, public_key = crypto.generate_key_pair()
        print("\n私钥 (请安全保存):")
        print(private_key)
        print("\n公钥 (可以分享):")
        print(public_key)

        # 加密示例
        message = input("\n请输入要加密的明文: ")
        encrypted = crypto.encrypt(public_key, message)
        print("\n加密后的密文 (16进制格式):")
        print(encrypted)

        # 解密示例
        decrypted = crypto.decrypt(private_key, encrypted)
        print("\n解密后的明文:")
        print(decrypted)

    except ValueError as e:
        print(f"\n错误: {str(e)}")
    except Exception as e:
        print(f"\n发生未知错误: {str(e)}")

if __name__ == "__main__":
    main() 
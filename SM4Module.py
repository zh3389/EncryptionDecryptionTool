from gmssl import sm4


class SM4ecb:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = sm4.CryptSM4()
        print(self.key, sm4.SM4_ENCRYPT)
        cipher.set_key(self.key, sm4.SM4_ENCRYPT)
        ciphertext = cipher.crypt_ecb(plaintext)
        return ciphertext.hex()

    def decrypt(self, ciphertext):
        ciphertext = bytes.fromhex(ciphertext)
        cipher = sm4.CryptSM4()
        cipher.set_key(self.key, sm4.SM4_DECRYPT)
        plaintext = cipher.crypt_ecb(ciphertext)
        return plaintext.decode('utf-8')

    def example(self):
        key = b'_siwei_c2l3ZWljbi5jb211ZWJh_2023-07-07_'
        plaintext = b'siwei123'
        encryptor = SM4ecb(key)
        encrypted_data = encryptor.encrypt(plaintext)
        print("Encrypted Data:", encrypted_data)
        decrypted_data = encryptor.decrypt(encrypted_data)
        print("Decrypted Data:", decrypted_data)


class SM4cbc:
    def __init__(self, key, iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
        self.key = key
        self.iv = iv

    def encrypt(self, plaintext):
        cipher = sm4.CryptSM4()
        cipher.set_key(self.key, sm4.SM4_ENCRYPT)
        ciphertext = cipher.crypt_cbc(self.iv, plaintext)  # bytes类型
        return ciphertext.hex()

    def decrypt(self, ciphertext):
        ciphertext = bytes.fromhex(ciphertext)
        cipher = sm4.CryptSM4()
        cipher.set_key(self.key, sm4.SM4_DECRYPT)
        plaintext = cipher.crypt_cbc(self.iv, ciphertext)  # bytes类型
        return plaintext.decode('utf-8')

    def example(self):
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        key = b'_siwei_c2l3ZWljbi5jb211ZWJh_2023-07-07_'
        plaintext = b'siwei123'
        encryptor = SM4cbc(key, iv)
        encrypted_data = encryptor.encrypt(plaintext)
        print("Encrypted Data:", encrypted_data)
        decrypted_data = encryptor.decrypt(encrypted_data)
        print("Decrypted Data:", decrypted_data)


if __name__ == '__main__':
    SM4ecb("1").example()
    SM4cbc("1").example()
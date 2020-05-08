# ~*~ coding: utf-8 ~*~
import base64

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


AES_SECRET_KEY = ""
AES_IV = ""
AES_MODE = AES.MODE_ECB


def aes_decrypt(source, key, iv):
    print('00: {}'.format(source))
    source_bytes = base64.b64decode(source)
    print('11: {}'.format(source_bytes))
    aes = AES.new(key.encode('utf-8'), AES_MODE)
    source_bytes = aes.decrypt(source_bytes)
    print('22: {}'.format(source_bytes))
    source_bytes = unpad(source_bytes, AES.block_size, style='pkcs7')
    print('33: {}'.format(source_bytes))
    source_decrypt = source_bytes.decode('utf-8')
    print('44: {}'.format(source_decrypt))
    return source_decrypt


def aes_encrypt(plain, key, iv):
    # aes = AES.new(key.encode(), ENCRYPT_AES_MODE, iv.encode())
    print('0: {}'.format(plain))
    plain_bytes = plain.encode('utf-8')
    print('1: {}'.format(plain_bytes))
    plain_bytes = pad(plain_bytes, AES.block_size, style='pkcs7')
    print('2: {}'.format(plain_bytes))
    aes = AES.new(key.encode(), AES_MODE)
    plain_bytes = aes.encrypt(plain_bytes)
    print('3: {}'.format(plain_bytes))
    plain_encrypt = base64.b64encode(plain_bytes).decode()
    print('4: {}'.format(plain_encrypt))
    return plain_encrypt


if __name__ == '__main__':
    test_password = "jumpserver"
    print("Origin: {}".format(test_password))
    encrypted = aes_encrypt(test_password, AES_SECRET_KEY, AES_IV)
    print("encrypted: {}".format(encrypted))
    decrypted = aes_decrypt(encrypted, AES_SECRET_KEY, AES_IV)
    print("decrypted: {}".format(decrypted))



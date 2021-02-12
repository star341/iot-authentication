# coding:utf-8
import sys
from base64 import *
import hmac
import time
from hashlib import md5
import random

from Crypto import Random
from Crypto.Cipher import AES
MY_ENCODING = "utf-8"


def pkcs7_padding(text):
    """
    The plaintext is padded using PKCS7
    When you finally call the AES encryption method, you pass in a byte array that
    is required to be multiple integers of 16, so you need to process the plaintext
    :param text: plaintext
    :return: bytes
    """
    bs = AES.block_size  # 16
    length = len(text)
    padding = bs - length % bs
    padding_text = padding.to_bytes(1, byteorder='big') * padding
    return text + padding_text


def pkcs7_unpadding(text):
    """
    Process data that has been padded with PKCS7
    :param text: The decrypted string
    :return: bytes
    """
    length = len(text)
    unpadding = text[length - 1]
    return text[0:length - unpadding]


def aes_encode(key, content):
    """
    AES encryption
    IV, 16 bytes, randomly generated
    mode: CBC
    padded by pkcs7
    :param key: bytes
    :param content: plaintext, str or bytes
    :return: Base64 encoded ciphertext (str)
    """
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding_content = pkcs7_padding(content)
    aes_encode_bytes = cipher.encrypt(padding_content)
    iv_cipher = iv + aes_encode_bytes
    result = str(b64encode(iv_cipher), encoding=MY_ENCODING)
    return result


def aes_decode(key, content):
    """
    AES decryption
     iv obtained from the first 16bytes of the ciphertext
    mode: CBC
    padded by pkcs7
    :param key: bytes
    :param content: Base64 encoded ciphertext (str)
    :return: plaintext (bytes)
    """
    iv_cipher = b64decode(bytes(content, encoding=MY_ENCODING))  # bytes
    iv = iv_cipher[:16]
    aes_encode_bytes = iv_cipher[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    aes_decode_bytes = cipher.decrypt(aes_encode_bytes)
    content = pkcs7_unpadding(aes_decode_bytes)
    return content


def hmac_md5(key, data):
    """
    Use MD5 for HMAC calculations
    :param key: bytes
    :param data: str
    :return: str
    """
    if type(data) is not bytes:
        data = bytes(data, encoding=MY_ENCODING)
    # 处理明文
    data_padding = pkcs7_padding(data)
    # data_bytes = bytes(data_padding, encoding=MY_ENCODING)
    hex_result = hmac.new(key, data_padding, digestmod='MD5').hexdigest()  # str
    return hex_result


def hash_md5_str(data):
    """
    Generate MD5 values for data
    :param data: str
    :return: md5 str 32bytes
    """
    if type(data) is str:
        data = data.encode(MY_ENCODING)
    md5_obj = md5(data)
    return md5_obj.hexdigest()


def hash_md5_bytes(data):
    """
    Generate MD5 values for data (16 bytes)
    :param data: str
    :return: md5: 16bytes
    """
    if type(data) is str:
        data = data.encode(MY_ENCODING)
    md5_obj = md5(data)
    return md5_obj.digest()


def create_salt(salt_len=16):
    salt = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    for i in range(salt_len):
        salt += random.choice(chars)
    return salt


def salted_hash_md5(salt, hash_password):
    md5_obj = md5()
    md5_obj.update((salt+hash_password).encode(MY_ENCODING))
    return md5_obj.hexdigest()

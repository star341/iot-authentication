import json
from base64 import *

# constants
RANDOM_BYTES = 16
MY_ENCODING = "utf-8"


def r_bytes2str(r: bytes) -> str:
    return str(b64encode(r), encoding=MY_ENCODING)


def r_str2bytes(r: str) -> bytes:
    return b64decode(bytes(r, encoding=MY_ENCODING))


def resolve_message_hmac(rec_data):
    rec_json = json.loads(rec_data)
    rec_message = rec_json["message"]
    rec_hmac = rec_json["hmac"]
    return rec_message, rec_hmac


def resolve_message(rec_data):
    rec_json = json.loads(rec_data)
    rec_message = rec_json["message"]
    return rec_message




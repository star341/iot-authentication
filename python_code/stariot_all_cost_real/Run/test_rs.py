import sys
from base64 import *
import json
import logging
import time
from twisted.internet import protocol
from twisted.internet import reactor


sys.path.append('../')
from Core.mycrypto import aes_encode, aes_decode,  hmac_md5
from Core.utils import MY_ENCODING, resolve_message_hmac, resolve_message


RS_PORT = 9002  # the port of RS

APP_ID_BYTES = 8
TOKEN_BYTES = 16
PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
HASH_MD5_STR_BYTES = 32
RS_ID_BYTES = 16
KDR_BYTES = 16
KRP_BYTES = 16
DELTA_TIME = 3
LOOP_TIMES = 1000

kra = b'1234567890123456'

connection_info = {}  # the connection information stored in RS, key is rs_id, values contains device_id,app_id,kdr,krp
sockets = {}  # RS store the sockets of device and app, keys are device_id and app_id


logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger('RS')



class RSServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            702: self.different705,
            706: self.different707,
            709: self.different710,
            712: self.different713,
            714: self.different715
        }

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('RS receives :' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 712 or code == 714:
            send_data = self.switch[code](rec_data)
        else:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info("time:%s RS sends %s"
                    % (end_time - start_time, send_data))
        if send_data:
            # logger.info('RS sends %s' % send_data)
            logger.info("communication_bytes:%s RS sends %s"
                        % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def different705(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(kra, encrypted_data)
        device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
        app_id = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
        rs_id = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RS_ID_BYTES]
        kdr = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+RS_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RS_ID_BYTES+KDR_BYTES]
        krp = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+RS_ID_BYTES+KDR_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RS_ID_BYTES+KDR_BYTES+KRP_BYTES]
        connection_info[rs_id] = {}
        connection_info[rs_id]["device_id"] = device_id
        connection_info[rs_id]["app_id"] = app_id
        connection_info[rs_id]["kdr"] = kdr
        connection_info[rs_id]["krp"] = krp

    def different707(self, rec_data):
        rec_message = resolve_message(rec_data)
        rs_id = b64decode(bytes(rec_message["rs_id"], encoding=MY_ENCODING))
        encrypted_data = rec_message["encrypted_data"]
        krp = connection_info[rs_id]["krp"]
        device_id = connection_info[rs_id]["device_id"]
        app_id = connection_info[rs_id]["app_id"]
        decrypted_data = aes_decode(krp, encrypted_data)
        if device_id == str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING) \
                and app_id == decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]:
            sockets[app_id] = self
            message = {
                "code": 707
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
            return send_data

    def different710(self, rec_data):
        rec_message = resolve_message(rec_data)
        rs_id = b64decode(bytes(rec_message["rs_id"], encoding=MY_ENCODING))
        encrypted_data = rec_message["encrypted_data"]
        kdr = connection_info[rs_id]["kdr"]
        device_id = connection_info[rs_id]["device_id"]
        decrypted_data = aes_decode(kdr, encrypted_data)
        if connection_info[rs_id]["device_id"] == str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING) and \
                connection_info[rs_id]["app_id"] == decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]:
            sockets[device_id] = self
            message = {
                "code": 710
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
            return send_data

    def different713(self, rec_data):
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            rs_id = b64decode(bytes(rec_message["rs_id"], encoding=MY_ENCODING))
            krp = connection_info[rs_id]["krp"]
            kdr = connection_info[rs_id]["kdr"]
            device_id = connection_info[rs_id]["device_id"]
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(krp, json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(krp, encrypted_data)
                # logger.info(" receives app sends: %s" % decrypted_data)
                encrypted_data = aes_encode(kdr, decrypted_data)
                message = {
                    "code": 713,
                    "time": int(time.time()),
                    "rs_id": str(b64encode(rs_id), encoding=MY_ENCODING),
                    "encrypted_data": encrypted_data
                }
                hmac = hmac_md5(kdr, json.dumps(message))
                send_json = {
                    "message": message,
                    "hmac": hmac
                }
                send_data = json.dumps(send_json)
        end_time = time.time_ns()
        sockets[device_id].transport.write(send_data.encode(MY_ENCODING))
        logger.info("time:%s communication_bytes:%s RS sends to device: %s"
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))

    def different715(self, rec_data):
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            start_time = time.time_ns()
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            rs_id = b64decode(bytes(rec_message["rs_id"], encoding=MY_ENCODING))
            app_id = connection_info[rs_id]["app_id"]
            krp = connection_info[rs_id]["krp"]
            kdr = connection_info[rs_id]["kdr"]
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(kdr, json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(kdr, encrypted_data)
                encrypted_data = aes_encode(krp, decrypted_data)
                message = {
                    "code": 715,
                    "time": int(time.time()),
                    "rs_id": str(b64encode(rs_id), encoding=MY_ENCODING),
                    "encrypted_data": encrypted_data
                }
                hmac = hmac_md5(krp, json.dumps(message))
                send_json = {
                    "message": message,
                    "hmac": hmac
                }
                send_data = json.dumps(send_json)
        end_time = time.time_ns()
        sockets[app_id].transport.write(send_data.encode(MY_ENCODING))
        logger.info("time:%s communication_bytes:%s RS sends to app:%s"
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))


class RSServerFactory(protocol.Factory):
    protocol = RSServer


def main():
    reactor.listenTCP(RS_PORT, RSServerFactory())
    logger.info('RS is running')
    reactor.run()


if __name__ == '__main__':
    main()

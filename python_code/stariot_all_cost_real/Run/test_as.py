# _*_coding:utf-8_*_
import sys
from base64 import *
import json
from twisted.internet import protocol
from twisted.internet import reactor
import pymysql
import logging
from Crypto import Random
from Crypto.Cipher import AES
import time
import re

sys.path.append('../')
from Core.mycrypto import aes_encode, aes_decode, hmac_md5, create_salt, hash_md5_bytes, hash_md5_str
from Core.utils import RANDOM_BYTES, MY_ENCODING, r_bytes2str, r_str2bytes, resolve_message_hmac, resolve_message


AS_PORT = 9003  # the port of AS
RS_HOST = 'localhost'  # the ip of RS
RS_PORT = 9002  # the port of RS

kap = b'ABCDEFGHIJKLMNOP'
kra = b'1234567890123456'

APP_ID_BYTES = 8
TOKEN_BYTES = 16
PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
HASH_MD5_STR_BYTES = 32
DELTA_TIME = 3
LOOP_TIMES = 1000


sockets = {}  # store the sockets of devices and apps, keys are device_id or app_id
to_rs_socket = None
bind_info = {}  # key is device_id, value is a dictionary with app_id, token and Kda
update_info = {}  # key is app_id, stores R, new_username, new_hash_password
rs_ids = []  # store all rs_id


logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger('AS')


class AuthServer(protocol.Protocol):
    def __init__(self):
        self.init_db()
        self.switch = {
            301: self.activation302,
            303: self.activation304,
            401: self.da_authentication402,
            403: self.da_authentication404,
            504: self.bind504,
            505: self.bind507,
            701: self.different702,
            801: self.update802,
            803: self.update804,
            901: self.recover902
        }
        self.activation_info = {}
        self.device_session = {}
        self.app_session = {}
        self.app_session["session_key"] = kap

    def init_db(self):
        self.conn = pymysql.connect(
            host='localhost',
            user='root',
            password='123456',
            database='as',
            charset='utf8'
        )
        self.cursor = self.conn.cursor()

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('AS receives :' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 505 or code == 701 or code == 801 or code == 803 or code == 901 or code == 303:
            send_data = self.switch[code](rec_data)
        else:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info("time:%s AS sends %s" % (end_time - start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s AS sends %s' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def activation302(self, rec_data):
        """
        AS issues DeviceSecret
        :param rec_data: str
        """
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        product_name = rec_message["device_id"][:PRODUCT_NAME_BYTES]  # str
        self.cursor.execute("select product_secret from product where product_name=%s", args=product_name)
        product_secret = self.cursor.fetchone()[0]  # bytes
        if hmac_md5(product_secret, json.dumps(rec_message)) == rec_hmac:
            device_id = rec_message["device_id"]
            device_secret = Random.new().read(AES.block_size)
            r2 = Random.new().read(AES.block_size)
            str_base64_r2 = r_bytes2str(r2)
            self.activation_info[device_id] = (device_secret, r2)
            encrypted_data = aes_encode(product_secret, device_secret)
            message = {
                "code": 302,
                "random": str_base64_r2,
                "encrypted_data": encrypted_data
            }
            hmac = hmac_md5(product_secret, json.dumps(message))
            send_json = {
                "message": message,
                "hmac": hmac
            }
            send_data = json.dumps(send_json)
            return send_data
        else:
            logger.info("the authentication of hmac failed in 302")

    def activation304(self, rec_data):
        """
        AS confirms if device get the DS, if successful, it will update DS and inform device.
        :param rec_data: str
        """
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        device_id = rec_message["device_id"]
        device_secret = self.activation_info[device_id][0]  # bytes
        r2 = self.activation_info[device_id][1]
        if aes_decode(device_secret, encrypted_data) == r2:
            self.cursor.execute('update device set device_secret=%s where device_id=%s',
                                args=(device_secret, device_id))
            self.conn.commit()
            str_base64_r3 = rec_message["random"]
            r3 = r_str2bytes(str_base64_r3)
            encrypted_data = aes_encode(device_secret, r3)
            message = {
                "code": 304,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            # logger.info("AS issues DS successfully, DS is: %s" % device_secret)
            return send_data
        else:
            logger.info("the response of r2 failed in 304")

    def da_authentication402(self, rec_data):
        """
        AS responses r4 from device and issues challenge r5
        :param rec_data: str
        """
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        device_id = rec_message["device_id"]
        self.cursor.execute("select device_secret from device where device_id=%s", args=device_id)
        device_secret = self.cursor.fetchone()[0]  # bytes
        self.device_session["device_id"] = device_id
        self.device_session["device_secret"] = device_secret
        r4 = aes_decode(device_secret, encrypted_data)
        r5 = Random.new().read(AES.block_size)
        self.device_session["r4"] = r4
        self.device_session["r5"] = r5
        encrypted_data = aes_encode(device_secret, r4 + r5)
        message = {
            "code": 402,
            "encrypted_data": encrypted_data
        }
        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        return send_data

    def da_authentication404(self, rec_data):
        """
        AS confirms if device responses successfully, if successful, he will generate the session key.
        :param rec_data: str
        """
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        device_id = rec_message["device_id"]
        device_secret = self.device_session["device_secret"]
        r4 = self.device_session["r4"]
        r5 = self.device_session["r5"]
        if aes_decode(device_secret, encrypted_data) == r5:
            sockets[device_id] = self
            self.device_session["session_key"] = hash_md5_bytes(r4 + r5)
            # logger.info("The session key negotiation between AS and Device is successful, session key is: {}"
            # .format(self.device_session["session_key"]))
            encrypted_data = aes_encode(self.device_session["session_key"], bytes(device_id, encoding=MY_ENCODING))
            message = {
                "code": 404,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
            return send_data

    def bind504(self, rec_data):
        rec_message = resolve_message(rec_data)
        device_id = rec_message["device_id"]
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.device_session["session_key"], encrypted_data)
        app_id = decrypted_data[:APP_ID_BYTES]
        token = decrypted_data[APP_ID_BYTES:APP_ID_BYTES+TOKEN_BYTES]
        bind_info[device_id] = {}
        bind_info[device_id]["session_key"] = self.device_session["session_key"]
        bind_info[device_id]["app_id"] = app_id
        bind_info[device_id]["token"] = token

    def bind506(self, device_id, send_data):
        start_time = time.time_ns()
        sockets[device_id].transport.write(send_data.encode(MY_ENCODING))
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s AS sends %s'
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data.encode(MY_ENCODING)))
        # logger.info('AS sends device: %s' % send_data)

    def bind507(self, rec_data):
        start_time = time.time_ns()
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.app_session["session_key"], encrypted_data)
        device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
        if device_id in bind_info and \
            bind_info[device_id]["app_id"] == decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES] and \
            bind_info[device_id]["token"] == decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+TOKEN_BYTES]:
            username_hash_password_bytes = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+TOKEN_BYTES:]
            username_hash_password_str = str(username_hash_password_bytes, encoding=MY_ENCODING)
            username = username_hash_password_str[:-(HASH_MD5_STR_BYTES+1)]
            hash_password = username_hash_password_str[-HASH_MD5_STR_BYTES:]
            salt = create_salt()
            salted_hash_password = hash_md5_str(salt + hash_password)
            klocal = hash_md5_bytes(device_id + str(b64encode(decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]), encoding=MY_ENCODING) + username + salted_hash_password)
            encrypted_data = aes_encode(bind_info[device_id]["session_key"], bind_info[device_id]["app_id"] + klocal)
            message = {
                "code": 506,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message,
            }
            send_data_device = json.dumps(send_json)
            encrypted_data = aes_encode(self.app_session["session_key"], bytes(device_id, encoding=MY_ENCODING) + bytes(salt, encoding=MY_ENCODING))
            message = {
                "code": 507,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message,
            }
            send_data_app = json.dumps(send_json)
            # store app_id into database
            self.cursor.execute('select count(*) from app where app_id=%s', args=bind_info[device_id]["app_id"])
            result = self.cursor.fetchone()[0]
            if result == 0:
                self.cursor.execute('insert into app(app_id) values(%s)',
                                    args=bind_info[device_id]["app_id"])
                self.conn.commit()
            self.cursor.execute('select count(*) from bind where device_id=%s and app_id=%s',
                                args=(device_id, bind_info[device_id]["app_id"]))
            result = self.cursor.fetchone()[0]
            # update the table "bind", insert if zero, update if bigger than zero
            if result == 0:
                self.cursor.execute('insert into bind(device_id, app_id, username, salted_hash_password, salt) values(%s, %s, %s, %s, %s)',
                                    args=(device_id, bind_info[device_id]["app_id"], username, salted_hash_password, salt))
                self.conn.commit()
            else:
                self.cursor.execute('update bind set username=%s, salted_hash_password=%s, salt=%s where device_id=%s and app_id=%s',
                                    args=(username, salted_hash_password, salt, device_id, bind_info[device_id]["app_id"]))
                self.conn.commit()
            end_time = time.time_ns()
            logger.info('bind507  time:%s' % (end_time - start_time))
            self.bind506(device_id, send_data_device)  # as sends success to device
            bind_info.pop(device_id)
            return send_data_app

    def different702(self, rec_data):
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and \
                    hmac_md5(self.app_session["session_key"], json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(self.app_session["session_key"], encrypted_data)
                device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
                app_id = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
                username_hash_password_bytes = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES:]
                username_hash_password_str = str(username_hash_password_bytes, encoding=MY_ENCODING)
                username = username_hash_password_str[:-(HASH_MD5_STR_BYTES+1)]
                hash_password = username_hash_password_str[-HASH_MD5_STR_BYTES:]
                self.cursor.execute('select salt, salted_hash_password from bind where device_id=%s and app_id=%s and username=%s',
                                    args=(device_id, app_id, username))
                salt, salted_hash_password = self.cursor.fetchone()
                temp_salted_hash_password = hash_md5_str(salt + hash_password)
                if temp_salted_hash_password == salted_hash_password:
                    sockets[app_id] = self
                    if device_id in sockets:
                        rs_id = Random.new().read(AES.block_size)
                        while rs_id in rs_ids:
                            rs_id = Random.new().read(AES.block_size)
                        kdr = Random.new().read(AES.block_size)
                        krp = Random.new().read(AES.block_size)
                        encrypted_data = aes_encode(kra, bytes(device_id, encoding=MY_ENCODING) + app_id + rs_id + kdr + krp)
                        message = {
                            "code": 702,
                            "encrypted_data": encrypted_data
                        }
                        send_json = {
                            "message": message,
                        }
                        send_data_rs = json.dumps(send_json)
                        rs_addr = RS_HOST + ':' + str(RS_PORT)
                        # logger.info("the address of RS is: %s" % rs_addr)
                        encrypted_data = aes_encode(self.app_session["session_key"], bytes(device_id, encoding=MY_ENCODING) + rs_id + krp +
                                                    bytes(rs_addr, encoding=MY_ENCODING))
                        message = {
                            "code": 703,
                            "encrypted_data": encrypted_data
                        }
                        send_json = {
                            "message": message,
                        }
                        send_data_app = json.dumps(send_json)
                        # logger.info('AS sends app: %s' % send_data_app)
                        encrypted_data = aes_encode(sockets[device_id].device_session["session_key"], app_id + rs_id +
                                                    kdr + bytes(rs_addr, encoding=MY_ENCODING))
                        message = {
                            "code": 704,
                            "encrypted_data": encrypted_data
                        }
                        send_json = {
                            "message": message,
                        }
                        send_data_device = json.dumps(send_json)
                        # logger.info('AS sends device: %s' % send_data_device)
        end_time = time.time_ns()
        to_rs_socket.transport.write(send_data_rs.encode(MY_ENCODING))
        logger.info('time:%s communication_bytes:%s AS sends RS: %s'
                    % (end_time - start_time, len(send_data_rs.encode(MY_ENCODING)), send_data_rs))
        sockets[app_id].transport.write(send_data_app.encode(MY_ENCODING))
        logger.info('time:%s communication_bytes:%s AS sends app: %s'
                    % (end_time - start_time, len(send_data_app.encode(MY_ENCODING)), send_data_app))
        logger.info('time:%s communication_bytes:%s AS sends 给device: %s'
                    % (end_time - start_time, len(send_data_device.encode(MY_ENCODING)), send_data_device))
        sockets[device_id].transport.write(send_data_device.encode(MY_ENCODING))

    def update802(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and \
                    hmac_md5(self.app_session["session_key"], json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(self.app_session["session_key"], encrypted_data)
                device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
                app_id = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
                r8 = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES]
                username_hash_password_bytes = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES:]
                username_hash_password_str = str(username_hash_password_bytes, encoding=MY_ENCODING)
                reg = '(.*?)&([0-9a-f]{%d})(.*?)&([0-9a-f]{%d})' %(HASH_MD5_STR_BYTES, HASH_MD5_STR_BYTES)
                result = re.match(reg, username_hash_password_str)
                old_username = result.group(1)
                old_hash_password = result.group(2)
                new_username = result.group(3)
                new_hash_password = result.group(4)
                self.cursor.execute('select salt, salted_hash_password from bind where device_id=%s and app_id=%s and username=%s',
                                    args=(device_id, app_id, old_username))
                try:
                    salt, salted_hash_password = self.cursor.fetchone()
                except:
                    logger.info("the user credential is wrong")
                    return
                temp_salted_hash_password = hash_md5_str(salt + old_hash_password)
                if temp_salted_hash_password == salted_hash_password:
                    sockets[app_id] = self
                    if device_id in sockets:
                        new_salt = create_salt()
                        update_info[app_id] = {}
                        update_info[app_id]["random"] = r8
                        update_info[app_id]["new_username"] = new_username
                        update_info[app_id]["new_hash_password"] = new_hash_password
                        update_info[app_id]["new_salt"] = new_salt
                        old_klocal = hash_md5_bytes(device_id + str(b64encode(decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]), encoding=MY_ENCODING) + old_username + hash_md5_str(salt + old_hash_password))
                        new_klocal = hash_md5_bytes(device_id + str(b64encode(decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]), encoding=MY_ENCODING) + new_username + hash_md5_str(new_salt + new_hash_password))
                        data = decrypted_data[:DEVICE_ID_BYTES] + app_id + r8 + old_klocal + new_klocal
                        encrypted_data = aes_encode(sockets[device_id].device_session["session_key"], data)
                        message = {
                            "code": 802,
                            "time": int(time.time()),
                            "encrypted_data": encrypted_data
                        }
                        hmac = hmac_md5(sockets[device_id].device_session["session_key"], json.dumps(message))
                        send_json = {
                            "message": message,
                            "hmac": hmac
                        }
                        send_data = json.dumps(send_json)
        logger.info("communication_bytes:%s as sends %s" % (len(send_data.encode(MY_ENCODING)), send_data))
        sockets[device_id].transport.write(send_data.encode(MY_ENCODING))

    def update804(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message = resolve_message(rec_data)
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.device_session["session_key"], encrypted_data)
            app_id = decrypted_data[:APP_ID_BYTES]
            r8 = decrypted_data[APP_ID_BYTES:APP_ID_BYTES+RANDOM_BYTES]
            if update_info[app_id]["random"] == r8:
                salted_hash_password = hash_md5_str(update_info[app_id]["new_salt"] + update_info[app_id]["new_hash_password"])
                self.cursor.execute(
                    'update bind set username=%s, salted_hash_password=%s, salt=%s where device_id=%s and app_id=%s',
                    args=(update_info[app_id]["new_username"], salted_hash_password, update_info[app_id]["new_salt"],
                          self.device_session["device_id"], app_id))
                self.conn.commit()
                # logger.info("has updated username as %s and salted_hash_password as %s whose app_id is %s and device_id is:%s"
                #             % (update_info[app_id]["new_username"], salted_hash_password), app_id, self.device_session["device_id"])
                encrypted_data = aes_encode(sockets[app_id].app_session["session_key"], r8 + bytes(update_info[app_id]["new_salt"], encoding=MY_ENCODING))
                message = {
                    "code": 804,
                    "encrypted_data": encrypted_data
                }
                send_json = {
                    "message": message,
                }
                send_data = json.dumps(send_json)
        logger.info("communication_bytes:%s as sends %s" % (len(send_data.encode(MY_ENCODING)), send_data))
        sockets[app_id].transport.write(send_data.encode(MY_ENCODING))
        # logger.info(" sends the successful information to app: %s" % send_data)

    def recover902(self, rec_data):
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        if int(time.time()) - rec_message["time"] <= DELTA_TIME and \
                hmac_md5(self.device_session["session_key"], json.dumps(rec_message)) == rec_hmac:
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.device_session["session_key"], encrypted_data)
            device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
            r9 = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+RANDOM_BYTES]
            if device_id == self.device_session["device_id"]:
                self.cursor.execute(
                    'delete from bind where device_id=%s', args=device_id)
                self.conn.commit()
                # logger.info("has deleted all binding information in %s" % device_id)
                encrypted_data = aes_encode(self.device_session["session_key"], r9)
                message = {
                    "code": 902,
                    "encrypted_data": encrypted_data
                }
                send_json = {
                    "message": message
                }
                send_data = json.dumps(send_json)
                return send_data



class DefaultServerFactory(protocol.Factory):
    protocol = AuthServer


class ASClient(protocol.Protocol):
    def connectionMade(self):
        logger.info('connects with RS successfully')
        global to_rs_socket
        to_rs_socket = self

    def dataReceived(self, data):
        pass


class ASClientFactory(protocol.ClientFactory):
    protocol = ASClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


def main():
    reactor.connectTCP(RS_HOST, RS_PORT, ASClientFactory())  # AS runs its local tcp client to connect with RS
    logger.info("AS runs its local tcp client to connect with RS")
    reactor.listenTCP(AS_PORT, DefaultServerFactory())
    logger.info("the server hosted in AS is running")
    reactor.run()


if __name__ == '__main__':
    main()

import re
import sys
from base64 import *
import json
import socket
from twisted.internet import protocol
from twisted.internet import reactor
import logging
import configparser
from Crypto import Random
from Crypto.Cipher import AES
import time

sys.path.append('../')
from Core.mycrypto import aes_encode, aes_decode, hmac_md5, hash_md5_bytes
from Core.utils import RANDOM_BYTES, MY_ENCODING, r_bytes2str, r_str2bytes, resolve_message_hmac, resolve_message


AS_HOST = 'localhost'  # the ip of AS
AS_PORT = 9003  # the port of AS
DEVICE_UDP_SERVER_HOST = ''  # the ip of UDP server hosted in the device
DEVICE_UDP_SERVER_PORT = 8001  # the port of UDP server hosted in the device
DEVICE_BIND_TCP_SERVER_HOST = 'localhost'  # the ip of TCP server hosted in the device in binding mode
DEVICE_BIND_TCP_SERVER_PORT = 9001  # the port of TCP server hosted in the device in binding mode
DEVICE_SAME_TCP_SERVER_PORT = 6001  #the port of local TCP server hosted in the device, used to communicate with app in LAN.

PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
APP_ID_BYTES = 8
TOKEN_BYTES = 16
KLOCAL_BYTES = 16
RS_ID_BYTES = 16
KDR_BYTES = 16
DELTA_TIME = 3
LOOP_TIMES = 1000
CONFIG_FILENAME = "device.conf"


kbind = b'1234567890123456'
bound = True
to_bind = False
to_recover = False
bind_app_id = None
bind_token = None
different_app_id = None
different_info = {}
klocals = {}

logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger('DEVICE')


def init_conf():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILENAME)
    return config


config = init_conf()


def read_conf():
    product_name = config['device']['product_name']
    try:
        product_secret = bytes(config['device']['product_secret'], encoding=MY_ENCODING)
    except Exception:
        product_secret = None
        logger.info(Exception)
    device_id = config['device']['device_id']
    try:
        device_secret = b64decode(bytes(config['device']['device_secret'], encoding=MY_ENCODING))
    except Exception:
        device_secret = None
        logger.info(Exception)
    all_sections = config.sections()
    klocals = {}
    for section in all_sections:
        if section != 'device':
            klocals[b64decode(bytes(section, encoding=MY_ENCODING))] = b64decode(config[section]['shared_key'])
    return [product_name, product_secret, device_id, device_secret, klocals]


PRODUCT_NAME, PRODUCT_SECRET, DEVICE_ID, DEVICE_SECRET, klocals = read_conf()


def is_bound(app_id: bytes) -> bool:
    return config.has_section(str(b64encode(app_id), encoding=MY_ENCODING))


def get_klocal(app_id: bytes) -> bytes:
    return b64decode(config[str(b64encode(app_id), encoding=MY_ENCODING)]['shared_key'])


def update_klocal(app_id: bytes, shared_key: bytes):
    config.set(str(b64encode(app_id), encoding=MY_ENCODING), 'shared_key', str(b64encode(shared_key), encoding=MY_ENCODING))
    config.write(open(CONFIG_FILENAME, "w"))


def add_bound(app_id: bytes, shared_key: bytes):
    if not config.has_section(str(b64encode(app_id), encoding=MY_ENCODING)):
        config.add_section(str(b64encode(app_id), encoding=MY_ENCODING))
        config.set(str(b64encode(app_id), encoding=MY_ENCODING), 'shared_key', str(b64encode(shared_key), encoding=MY_ENCODING))
        config.write(open(CONFIG_FILENAME, "w"))


def set_device_secret(device_secret: bytes):
    config.set('device', 'device_secret', str(b64encode(device_secret), encoding=MY_ENCODING))
    config.write(open(CONFIG_FILENAME, "w"))


def delete_product_secret():
    config.remove_option('device', 'product_secret')
    config.write(open(CONFIG_FILENAME, "w"))


def is_activated():
    return config.has_option('device', 'device_secret')


def delete_all_bound():
    for section in config.sections():
        if config.has_option(section, 'shared_key'):
            config.remove_section(section)
    config.write(open(CONFIG_FILENAME, "w"))


class DeviceRegistrationClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            302: self.activation303,
            304: self.activation305,
        }
        self.activation_info = {}

    def connectionMade(self):
        logger.info('The connection between Device and AS is successful')
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            if not is_activated():
                send_data = self.activation301()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s device send:%s'
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))
        self.transport.write(send_data.encode(MY_ENCODING))

    def dataReceived(self, rec_data):
        rec_data = rec_data.decode(MY_ENCODING)
        logger.info('device receives: ' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 704:
            send_data = self.switch[code](rec_data)
        else:
            if code == 304:
                send_data = self.switch[code](rec_data)
            else:
                for i in range(LOOP_TIMES):
                    send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info("time:%s device sends: %s" % (end_time - start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s device sends: %s' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def activation301(self):
        """
        device request for DeviceSecret
        """
        r1 = Random.new().read(AES.block_size)  # bytes
        str_base64_r1 = r_bytes2str(r1)
        message = {
            "code": 301,
            "device_id": DEVICE_ID,
            "random": str_base64_r1,
        }
        hmac = hmac_md5(PRODUCT_SECRET, json.dumps(message))
        send_json = {
            "message": message,
            "hmac": hmac
        }
        send_data = json.dumps(send_json)
        return send_data

    def activation303(self, rec_data):
        """
        device authenticates hmac, get DS, and confirm to AS
        :param rec_data: str
        """
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        if hmac_md5(PRODUCT_SECRET, json.dumps(rec_message)) == rec_hmac:
            temp_device_secret = aes_decode(PRODUCT_SECRET, encrypted_data)  # bytes
            # logger.info("device gets DS: %s" % temp_device_secret)
            str_base64_r2 = rec_message["random"]
            r2 = r_str2bytes(str_base64_r2)
            encrypted_data = aes_encode(temp_device_secret, r2)
            r3 = Random.new().read(AES.block_size)
            str_base64_r3 = r_bytes2str(r3)  # str
            self.activation_info['r3'] = r3
            self.activation_info['device_secret'] = temp_device_secret
            message = {
                "code": 303,
                "device_id": DEVICE_ID,
                "random": str_base64_r3,
                "encrypted_data": encrypted_data,
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
            return send_data
        else:
            logger.info("in 303: the authentication of hmac failed")

    def activation305(self, rec_data):
        """
        device authenticates r3, deletes PS, and add DEVICE_SECRET in device.conf
        :param rec_data: str
        """
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        if aes_decode(self.activation_info['device_secret'], encrypted_data) == self.activation_info['r3']:
            set_device_secret(self.activation_info['device_secret'])
            delete_product_secret()
            # logger.info("device update DS: %s" % self.activation_info['device_secret'])
            # logger.info("store DS and delete PS successfully")
        else:
            logger.info("the response of r2 failed")


class DeviceRegistrationClientFactory(protocol.ClientFactory):
    protocol = DeviceRegistrationClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


class EchoServer(protocol.DatagramProtocol):  # the UDP server hosted in the device, waits for a connection from app in LAN
    def startProtocol(self):
        logger.info('device\'s UDP server is running, port is %s' % DEVICE_UDP_SERVER_PORT)
        self.transport.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

    def datagramReceived(self, datagram, addr):
        logger.info("[device\'s UDP server]  receives a message from %s:%s" % addr)
        rec_data = datagram.decode(MY_ENCODING)
        logger.info("[device\'s UDP server]  receives a message: %s" % rec_data)
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            rec_json = json.loads(rec_data)
            rec_message = rec_json["message"]
            if rec_message["code"] == 601 and rec_message["device_id"] == DEVICE_ID:
                message = {
                    "code": 602,
                    "device_id": DEVICE_ID
                }
                send_json = {
                    "message": message,
                }
                send_data = json.dumps(send_json)
        end_time = time.time_ns()
        self.transport.write(send_data.encode(MY_ENCODING), addr)
        logger.info("time:%s communication_bytes:%s [device's UDP server] sends %s"
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))
            
            
class DeviceClient(protocol.Protocol):  # the client of the device, communicates with AS
    def __init__(self):
        self.switch = {
            402: self.da_authentication403,
            404: self.da_authentication405,
            506: self.bind508,
            704: self.different709,
            802: self.update803,
            902: self.recover903
        }
        self.as_session = {}
        self.recover_info = {}

    def connectionMade(self):
        logger.info('The connection between Device and AS is successful')
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            send_data = self.da_authentication401()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s device sends:%s'
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))
        self.transport.write(send_data.encode(MY_ENCODING))

    def dataReceived(self, rec_data):
        rec_data = rec_data.decode(MY_ENCODING)
        logger.info('device receives:' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 704 or code == 506 or code == 802 or code == 902:
            send_data = self.switch[code](rec_data)
        else:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info("time:%s device sends %s" % (end_time - start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s device sends %s' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def da_authentication401(self):
        """
        The device challenges the AS
        """
        self.as_session["r4"] = Random.new().read(AES.block_size)  # bytes
        encrypted_data = aes_encode(DEVICE_SECRET, self.as_session["r4"])
        message = {
            "code": 401,
            "device_id": DEVICE_ID,
            "encrypted_data": encrypted_data
        }
        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        return send_data

    def da_authentication403(self, rec_data):
        """
        device responses to AS, and genereates the session key
        :param rec_data: str
        """
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(DEVICE_SECRET, encrypted_data)
        r4 = decrypted_data[:RANDOM_BYTES]
        r5 = decrypted_data[RANDOM_BYTES:]
        # bind_flag = 1 if to_bind else 0
        if r4 == self.as_session["r4"]:
            encrypted_data = aes_encode(DEVICE_SECRET, r5)
            message = {
                "code": 403,
                # "for_bind": bind_flag,
                "device_id": DEVICE_ID,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            # self.as_session["session_key"] = bxor(r4, r5)
            self.as_session["session_key"] = hash_md5_bytes(r4 + r5)
            return send_data
        else:
            logger.info("in 403, the challenge failed")

    def da_authentication405(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.as_session["session_key"], encrypted_data)
        if DEVICE_ID == str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING):
            # logger.info("The session key negotiation between Device and AS is successful:{}".format(self.as_session["session_key"]))
            if to_bind:
                encrypted_data = aes_encode(self.as_session["session_key"], bind_app_id + bind_token)
                message = {
                    "code": 504,
                    "device_id": DEVICE_ID,
                    "encrypted_data": encrypted_data
                }
                send_json = {
                    "message": message,
                }
                send_data = json.dumps(send_json)
                return send_data
            elif to_recover:
                return self.recover901()
        else:
            raise Exception("The session key negotiation between Device and AS failed")

    def bind508(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.as_session["session_key"], encrypted_data)
        app_id = decrypted_data[:APP_ID_BYTES]
        klocal = decrypted_data[APP_ID_BYTES:APP_ID_BYTES+KLOCAL_BYTES]
        global to_bind
        to_bind = False
        add_bound(app_id, klocal)
        # logger.info("bind successfully with app:%s, store klocal:%s" % (app_id, klocal))

    def different709(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message = resolve_message(rec_data)
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.as_session["session_key"], encrypted_data)
            app_id = decrypted_data[:APP_ID_BYTES]
            global different_app_id
            different_app_id = app_id
            rs_id = decrypted_data[APP_ID_BYTES:APP_ID_BYTES+RS_ID_BYTES]
            kdr = decrypted_data[APP_ID_BYTES+RS_ID_BYTES:APP_ID_BYTES+RS_ID_BYTES+KDR_BYTES]
            rs_addr_plus_padding = str(decrypted_data[APP_ID_BYTES+RS_ID_BYTES+KDR_BYTES:], encoding=MY_ENCODING)
            result = re.match('([^#]*)(#*)', rs_addr_plus_padding)
            rs_addr = result.group(1)
            # logger.info("the address of RS is %s" % rs_addr)
            rs_host, rs_port = rs_addr.split(':')
            encrypted_data = aes_encode(kdr, bytes(DEVICE_ID, encoding=MY_ENCODING) + app_id)
            message = {
                "code": 709,
                "rs_id": str(b64encode(rs_id), encoding=MY_ENCODING),
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            different_info[app_id] = {}
            different_info[app_id]["connection_data"] = send_data
            different_info[app_id]["kdr"] = kdr
            different_info[app_id]["rs_id"] = rs_id
        # connect with RS
        reactor.connectTCP(rs_host, int(rs_port), DeviceDifferentRSClientFactory())

    def update803(self, rec_data):
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        if int(time.time()) - rec_message["time"] <= DELTA_TIME and \
                hmac_md5(self.as_session["session_key"], json.dumps(rec_message)) == rec_hmac:
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.as_session["session_key"], encrypted_data)
            device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
            app_id = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
            r8 = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES]
            old_klocal = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES+KLOCAL_BYTES]
            new_klocal = decrypted_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES+KLOCAL_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES+2*KLOCAL_BYTES]
            if device_id == DEVICE_ID and old_klocal == get_klocal(app_id):
                # update klocal
                update_klocal(app_id, new_klocal)
                klocals[app_id] = new_klocal
                data = app_id + r8
                encrypted_data = aes_encode(self.as_session["session_key"], data)
                message = {
                    "code": 803,
                    "encrypted_data": encrypted_data
                }
                send_json = {
                    "message": message,
                }
                send_data = json.dumps(send_json)
                return send_data

    def recover901(self):
        r9 = Random.new().read(AES.block_size)
        self.recover_info["random"] = r9
        encrypted_data = aes_encode(self.as_session["session_key"], bytes(DEVICE_ID, encoding=MY_ENCODING) + r9)
        message = {
            "code": 901,
            "time": int(time.time()),
            "encrypted_data": encrypted_data
        }
        hmac = hmac_md5(self.as_session["session_key"], json.dumps(message))
        send_json = {
            "message": message,
            "hmac": hmac
        }
        send_data = json.dumps(send_json)
        return send_data

    def recover903(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.as_session["session_key"], encrypted_data)
        if (decrypted_data[:RANDOM_BYTES] == self.recover_info["random"]):
            delete_all_bound()
            # logger.info("Restore factory settings successfully, and delete user credentials")


class DeviceClientFactory(protocol.ClientFactory):
    protocol = DeviceClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


class DeviceBindServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            501: self.bind502,
            503: self.bind504
        }

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('device_server receives :' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code != 503:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        else:
            send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s device_server sends %s' % (end_time - start_time, send_data))
        if send_data:
            logger.info("communication_bytes:%s device_server sends %s" % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def bind502(self, rec_data):
        rec_json = json.loads(rec_data)
        rec_message = rec_json["message"]  # a broadcast package from app
        #  sends SD to app
        device_id = DEVICE_ID
        encrypted_data = aes_encode(kbind, bytes(device_id, encoding=MY_ENCODING))
        message = {
            "code": 502,
            "encrypted_data": encrypted_data
        }
        send_json = {
            "message": message,
        }
        send_data = json.dumps(send_json)
        return send_data

    def bind504(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_json = json.loads(rec_data)
            rec_message = rec_json["message"]
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(kbind, encrypted_data)
            app_id = decrypted_data[:APP_ID_BYTES]
            token = decrypted_data[APP_ID_BYTES:APP_ID_BYTES + TOKEN_BYTES]
            global bind_app_id, bind_token
            bind_app_id = app_id
            bind_token = token
            global bound
        if not is_bound(app_id):
            bound = False
            global to_bind
            to_bind = True
            reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
        else:
            bound = True
            logger.info('app has bound me')


class DeviceBindServerFactory(protocol.Factory):
    protocol = DeviceBindServer


class DeviceSameServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            603: self.same604,
            605: self.same606,
            608: self.same609
        }
        self.app_session = {}

    def connectionMade(self):
        logger.info("In LAN, the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('[the tcp server hosted in the device] receives: {}'.format(rec_data))
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        for i in range(LOOP_TIMES):
            send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s device_same_server sends %s' % (end_time-start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s device_same_server sends %s' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def same604(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        app_id = b64decode(bytes(rec_message["app_id"], encoding=MY_ENCODING))
        if is_bound(app_id):
            klocal = klocals[app_id]  # bytes
            self.app_session["app_id"] = app_id
            self.app_session["klocal"] = klocal
            r6 = aes_decode(klocal, encrypted_data)
            r7 = Random.new().read(AES.block_size)
            self.app_session["r6"] = r6
            self.app_session["r7"] = r7
            encrypted_data = aes_encode(klocal, r6 + r7)
            message = {
                "code": 604,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            return send_data

    def same606(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        app_id = b64decode(bytes(rec_message["app_id"], encoding=MY_ENCODING))
        klocal = self.app_session["klocal"]
        r6 = self.app_session["r6"]
        r7 = self.app_session["r7"]
        if aes_decode(klocal, encrypted_data) == r7:
            self.app_session["session_key"] = hash_md5_bytes(r6+r7)
            # del self.app_session["r6"]
            # del self.app_session["r7"]
            # logger.info("The session key negotiation with APP is successful]: {}".format(self.app_session["session_key"]))
            encrypted_data = aes_encode(self.app_session["session_key"], app_id)
            message = {
                "code": 606,
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
            return send_data
        else:
            raise Exception("The session key negotiation with APP is failed")

    def same609(self, rec_data):
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(self.app_session["session_key"], json.dumps(rec_message)) == rec_hmac:
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.app_session["session_key"], encrypted_data)
            # logger.info(" receives a message from app: %s" % decrypted_data)
            data = b'M2'
            encrypted_data = aes_encode(self.app_session["session_key"], data)
            message = {
                "code": 609,
                "time": int(time.time()),
                "encrypted_data": encrypted_data
            }
            hmac = hmac_md5(self.app_session["session_key"], json.dumps(message))
            send_json = {
                "message": message,
                "hmac": hmac
            }
            send_data = json.dumps(send_json)
            return send_data


class DeviceSameServerFactory(protocol.Factory):
    protocol = DeviceSameServer


class DeviceDifferentRSClient(protocol.Protocol):
    def __init__(self):
        self.different_app_id = different_app_id
        self.kdr = different_info[self.different_app_id]["kdr"]
        self.rs_id = different_info[self.different_app_id]["rs_id"]
        self.connection_data = different_info[self.different_app_id]["connection_data"]
        self.switch = {
            710: self.different711,
            713: self.different714
        }
    def connectionMade(self):
        logger.info('communication_bytes:%s' % (len(self.connection_data.encode(MY_ENCODING))))
        self.transport.write(self.connection_data.encode(MY_ENCODING))
        logger.info("device sends %s to RS" % self.connection_data)

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('device receives from RS:' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s device sends %s to RS' % (end_time-start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s device sends %s to RS' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def connectionLost(self, reason):
        logger.info('the server is closed')

    def different711(self, rec_data):
        logger.info('connects with RS successfully')

    def different714(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(self.kdr, json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(self.kdr, encrypted_data)
                # logger.info(" receives a message from RS: %s" % decrypted_data)
                data = b'M4'
                encrypted_data = aes_encode(self.kdr, data)
                message = {
                    "code": 714,
                    "time": int(time.time()),
                    "rs_id": str(b64encode(self.rs_id), encoding=MY_ENCODING),
                    "encrypted_data": encrypted_data
                }
                hmac = hmac_md5(self.kdr, json.dumps(message))
                send_json = {
                    "message": message,
                    "hmac": hmac
                }
                send_data = json.dumps(send_json)
        return send_data


class DeviceDifferentRSClientFactory(protocol.ClientFactory):
    protocol = DeviceDifferentRSClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()
    
    
def main():
    mode = input("please choose the mode, 1: activation 2:bind 3:communication 4:restore factory setting ")
    if mode == '1':
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceRegistrationClientFactory())
    elif mode == '2':
        reactor.listenTCP(DEVICE_BIND_TCP_SERVER_PORT, DeviceBindServerFactory())
    elif mode == '3':
        reactor.listenTCP(DEVICE_SAME_TCP_SERVER_PORT, DeviceSameServerFactory())
        reactor.listenUDP(DEVICE_UDP_SERVER_PORT, EchoServer(), DEVICE_UDP_SERVER_HOST)
        logger.info("device's UDP server is running")
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
    elif mode == '4':
        global to_recover
        to_recover = True
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
    reactor.run()


if __name__ == '__main__':
    main()

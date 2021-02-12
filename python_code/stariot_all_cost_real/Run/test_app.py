# _*_coding:utf-8_*_
import re
import sys
from base64 import *
import json
from twisted.internet import protocol
from twisted.internet import reactor
import logging
import configparser
from Crypto import Random
from Crypto.Cipher import AES
import time
from socket import SOL_SOCKET, SO_BROADCAST

sys.path.append('../')
from Core.mycrypto import aes_encode, aes_decode, hash_md5_bytes, hash_md5_str, hmac_md5
from Core.utils import RANDOM_BYTES, MY_ENCODING, resolve_message_hmac, resolve_message

AS_HOST = 'localhost'  # the ip of AS
AS_PORT = 9003  # the port of AS
DEVICE_UDP_SERVER_PORT = 8001  # the port of device's UDP server
DEVICE_BIND_TCP_SERVER_HOST = 'localhost'  # the ip of TCP server hosted in the device in binding mode
DEVICE_BIND_TCP_SERVER_PORT = 9001  # the port of TCP server hosted in the device in binding mode
BROADCAST_HOST = '255.255.255.255'
DEVICE_SAME_TCP_SERVER_PORT = 6001  # the local TCP server hosted in the device, communicating with app in LAN

PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
APP_ID_BYTES = 8
RS_ID_BYTES = 16
KRP_BYTES = 16
SALT_BYTES = 16
DELTA_TIME = 3
LOOP_TIMES = 1000

kbind = b'1234567890123456'
kap = b'ABCDEFGHIJKLMNOP'
app_id = b'iamappjj'
username = 'starstarstarstar'
password = 'haha'
update_mode = False
new_username = 'starstarstarstar'
new_password = 'haha'
bind_info = {}  # store app_id and token
bind_request_as = False
different_device_id = None
different_info = {}
bound_devices_id = []
devices_salt = {}
CONFIG_FILENAME = "app.conf"

logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger('APP')


def init_conf():
    myconfig = configparser.ConfigParser()
    myconfig.read(CONFIG_FILENAME)
    return myconfig


config = init_conf()


def get_bound(device_id):
    return config.has_section(device_id)


def set_bound(device_id, salt):
    if not config.has_section(device_id):
        config.add_section(device_id)
        config.write(open(CONFIG_FILENAME, "w"))
        config.set(device_id, 'salt', salt)
        config.write(open(CONFIG_FILENAME, "w"))


def update_salt(device_id, salt):
    if config.has_section(device_id):
        config.set(device_id, 'salt', salt)
        config.write(open(CONFIG_FILENAME, "w"))


def get_salts():
    all_sections = config.sections()
    all_devices_salt = {}
    for section in all_sections:
        all_devices_salt[section] = config[section]['salt']
    return all_devices_salt


def get_bound_devices_id() -> list:
    return config.sections()


bound_devices_id = get_bound_devices_id()
devices_salt = get_salts()
lan_device_id = None


class EchoClientDatagramProtocol(protocol.DatagramProtocol):

    def startProtocol(self):
        self.transport.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, True)
        self.sendDatagram()

    def sendDatagram(self):
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            message = {
                "code": 601,
                "device_id": bound_devices_id[0]  # suppose APP wants to communicate with the first device in LAN
            }
            send_json = {
                "message": message,
            }
            send_data = json.dumps(send_json)
        end_time = time.time_ns()
        logger.info("time:%s communication_bytes:%s app sends a broadcast package to discover the device"
                    % (end_time-start_time, len(send_data.encode(MY_ENCODING))))
        self.transport.write(send_data.encode(MY_ENCODING), (BROADCAST_HOST, DEVICE_UDP_SERVER_PORT))

    def datagramReceived(self, datagram, addr):
        rec_data = datagram.decode(MY_ENCODING)
        logger.info("[app udp client] receives a message from: {}:{}, the message is: {}"
                    .format(addr[0], addr[1], rec_data))
        rec_json = json.loads(rec_data)
        rec_message = rec_json["message"]
        if rec_message["code"] == 602 and rec_message["device_id"] in bound_devices_id:
            global lan_device_id
            lan_device_id = rec_message["device_id"]
            reactor.connectTCP(addr[0], DEVICE_SAME_TCP_SERVER_PORT, AppSameClientFactory())
            logger.info("tcp server is running")
            
            
class AppBindClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            502: self.bind503,
            507: self.bind509
        }
        self.as_session = {}

    def connectionMade(self):
        logger.info('connects with device successfully, the device is: %s' % self.transport.getPeer())
        start_time = time.time_ns()
        if bind_request_as == False:
            for i in range(LOOP_TIMES):
                send_data = self.bind501()
        else:
            # suppose app sleep 3 seconds
            time.sleep(3)
            for i in range(LOOP_TIMES):
                send_data = self.bind505()
        end_time = time.time_ns()
        logger.info("time:%s communication_bytes:%s device_server sends %s"
                    % (end_time - start_time, len(send_data.encode(MY_ENCODING)), send_data))
        self.transport.write(send_data.encode(MY_ENCODING))

    def dataReceived(self, rec_data):
        rec_data = rec_data.decode(MY_ENCODING)
        logger.info('app receives :' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 507:
            send_data = self.switch[code](rec_data)
        else:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s app sends %s' % (end_time - start_time, send_data))
        if send_data:
            logger.info('app sends ' + send_data)
            logger.info("communication_bytes:%s app sends %s" % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))
            if bind_request_as == True:
                # send a request to AS for binding device
                reactor.connectTCP(AS_HOST, AS_PORT, AppBindClientFactory())

    def bind501(self):
        message = {
            "code": 501
        }
        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        return send_data

    def bind503(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        device_id = str(aes_decode(kbind, encrypted_data)[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
        if device_id in bound_devices_id:
            logger.info("has bound device: %s" % device_id)
            rebind_flag = True
            if rebind_flag:
                logger.info("to bind the device: %s again" % device_id)
            else:
                logger.info("do not bind the device: %s twice" % device_id)
                return
        token = Random.new().read(AES.block_size)
        bind_info["device_id"] = device_id
        bind_info["token"] = token
        encrypted_data = aes_encode(kbind, app_id + token)
        message = {
            "code": 503,
            "encrypted_data": encrypted_data
        }
        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        global bind_request_as
        bind_request_as = True
        return send_data

    def bind505(self):
        data = bytes(bind_info["device_id"], encoding=MY_ENCODING) + app_id + bind_info["token"] + \
               bytes(username, encoding=MY_ENCODING) + b'&' + bytes(hash_md5_str(password), encoding=MY_ENCODING)
        encrypted_data = aes_encode(kap, data)
        message = {
            "code": 505,
            "encrypted_data": encrypted_data
        }

        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        return send_data

    def bind509(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        device_id = str(aes_decode(kap, encrypted_data)[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
        salt = str(aes_decode(kap, encrypted_data)[DEVICE_ID_BYTES:DEVICE_ID_BYTES + SALT_BYTES], encoding=MY_ENCODING)
        if device_id in bind_info.values():
            # logger.info("bind the device:%s successfully" % device_id)
            pass
        set_bound(device_id, salt)
        global bind_request_as
        bind_request_as = False


class AppBindClientFactory(protocol.ClientFactory):
    protocol = AppBindClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class AppSameClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            604: self.same605,
            606: self.same607,
            609: self.same610
        }
        self.device_session = {}

    def connectionMade(self):
        logger.info("connects with the local tcp server hosted in the device successfully: {}"
                    .format(self.transport.getPeer()))
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            send_data = self.same603()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s[TCP client] sends the local tcp server hosted in the device: %s'
                    % (end_time-start_time, len(send_data.encode(MY_ENCODING)), send_data))
        self.transport.write(send_data.encode(MY_ENCODING))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('[TCP client] receives: {}'.format(rec_data))
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        for i in range(LOOP_TIMES):
            send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s [TCP client] sends %s' % (end_time-start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s [TCP client] sends %s'
                        % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def same603(self):
        salt = devices_salt[bound_devices_id[0]]  # suppose to communicate with the first bound device in LAN
        self.klocal = hash_md5_bytes(lan_device_id + str(b64encode(app_id), encoding=MY_ENCODING)
                                     + username + hash_md5_str(salt + hash_md5_str(password)))
        r6 = Random.new().read(AES.block_size)
        self.device_session["r6"] = r6
        encrypted_data = aes_encode(self.klocal, r6)
        message = {
            "code": 603,
            "app_id": str(b64encode(app_id), encoding=MY_ENCODING),
            "encrypted_data": encrypted_data
        }
        send_json = {
            "message": message
        }
        send_data = json.dumps(send_json)
        return send_data

    def same605(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.klocal, encrypted_data)
        r6 = decrypted_data[:RANDOM_BYTES]
        r7 = decrypted_data[RANDOM_BYTES:]
        if r6 == self.device_session["r6"]:
            encrypted_data = aes_encode(self.klocal, r7)
            message = {
                "code": 605,
                "app_id": str(b64encode(app_id), encoding=MY_ENCODING),
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            self.device_session["session_key"] = hash_md5_bytes(r6+r7)
            return send_data
        else:
            logger.info("the challenge of r7 failed in 605")

    def same607(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(self.device_session["session_key"], encrypted_data)
        if app_id == decrypted_data[:APP_ID_BYTES]:
            # logger.info("Session key negotiation with device successed: {}".format(self.device_session["session_key"]))
            return self.same608()
        else:
            raise Exception("Session key negotiation with device failed")

    def same608(self):
        data = b'M1'
        encrypted_data = aes_encode(self.device_session["session_key"], data)
        message = {
            "code": 608,
            "time": int(time.time()),
            "encrypted_data": encrypted_data
        }
        hmac = hmac_md5(self.device_session["session_key"], json.dumps(message))
        send_json = {
            "message": message,
            "hmac": hmac
        }
        send_data = json.dumps(send_json)
        return send_data

    def same610(self, rec_data):
        rec_message, rec_hmac = resolve_message_hmac(rec_data)
        if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(self.device_session["session_key"],
                                                                             json.dumps(rec_message)) == rec_hmac:
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(self.device_session["session_key"], encrypted_data)
            # logger.info(" receives a message from the device: %s" % decrypted_data)
            # return self.same608()  # keep communicating


class AppSameClientFactory(protocol.ClientFactory):
    protocol = AppSameClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class AppDifferentASClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            703: self.different706,
            804: self.update805
        }
        self.device_session = {}
        self.update_info = {}

    def connectionMade(self):
        logger.info("connects with AS successfully: {}".format(self.transport.getPeer()))
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            if update_mode:
                send_data = self.update801()
            else:
                send_data = self.different701()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s[tcp client] sends %s'
                    % (end_time-start_time, len(send_data.encode(MY_ENCODING)), send_data))
        self.transport.write(send_data.encode(MY_ENCODING))

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('[tcp client] receives: {}'.format(rec_data))
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        if code == 703:
            send_data = self.switch[code](rec_data)
        else:
            for i in range(LOOP_TIMES):
                send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s [tcp client] sends %s' % (end_time-start_time, send_data))
        if send_data:
            logger.info('[tcp client] sends %s' % send_data)
            self.transport.write(send_data.encode(MY_ENCODING))

    def different701(self):
        # suppose APP wants to communicate with the first device in public network
        data = bytes(bound_devices_id[0], encoding=MY_ENCODING) + app_id + \
               bytes(username, encoding=MY_ENCODING) + b'&' + bytes(hash_md5_str(password), encoding=MY_ENCODING)
        encrypted_data = aes_encode(kap, data)
        message = {
            "code": 701,
            "time": int(time.time()),
            "encrypted_data": encrypted_data
        }
        hmac = hmac_md5(kap, json.dumps(message))
        send_json = {
            "message": message,
            "hmac": hmac
        }
        send_data = json.dumps(send_json)
        return send_data

    def different706(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message = resolve_message(rec_data)
            encrypted_data = rec_message["encrypted_data"]
            decrypted_data = aes_decode(kap, encrypted_data)
            device_id = str(decrypted_data[:DEVICE_ID_BYTES], encoding=MY_ENCODING)
            global different_device_id
            different_device_id = device_id
            rs_id = decrypted_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+RS_ID_BYTES]
            krp = decrypted_data[DEVICE_ID_BYTES+RS_ID_BYTES:DEVICE_ID_BYTES+RS_ID_BYTES+KRP_BYTES]
            rs_addr_plus_padding = str(decrypted_data[DEVICE_ID_BYTES+RS_ID_BYTES+KRP_BYTES:], encoding=MY_ENCODING)
            result = re.match('([^#]*)(#*)', rs_addr_plus_padding)
            rs_addr = result.group(1)
            # logger.info("get the address of RS: %s" % rs_addr)
            rs_host, rs_port = rs_addr.split(':')
            encrypted_data = aes_encode(krp, decrypted_data[:DEVICE_ID_BYTES] + app_id)
            message = {
                "code": 706,
                "rs_id": str(b64encode(rs_id), encoding=MY_ENCODING),
                "encrypted_data": encrypted_data
            }
            send_json = {
                "message": message
            }
            send_data = json.dumps(send_json)
            different_info[device_id] = {}
            different_info[device_id]["connection_data"] = send_data
            different_info[device_id]["krp"] = krp
            different_info[device_id]["rs_id"] = rs_id
        # run the client communicating with RS
        reactor.connectTCP(rs_host, int(rs_port), AppDifferentRSClientFactory())

    def update801(self):
        R = Random.new().read(AES.block_size)
        self.update_info["random"] = R
        self.update_info["device_id"] = bound_devices_id[0]
        # ready to update the user credential of the first device
        data = bytes(self.update_info["device_id"], encoding=MY_ENCODING) + app_id + R + \
               bytes(username, encoding=MY_ENCODING) + b'&' + bytes(hash_md5_str(password), encoding=MY_ENCODING) + \
               bytes(new_username, encoding=MY_ENCODING) + b'&' + bytes(hash_md5_str(new_password), encoding=MY_ENCODING)
        encrypted_data = aes_encode(kap, data)
        message = {
            "code": 801,
            "time": int(time.time()),
            "encrypted_data": encrypted_data
        }
        hmac = hmac_md5(kap, json.dumps(message))
        send_json = {
            "message": message,
            "hmac": hmac
        }
        send_data = json.dumps(send_json)
        return send_data

    def update805(self, rec_data):
        rec_message = resolve_message(rec_data)
        encrypted_data = rec_message["encrypted_data"]
        decrypted_data = aes_decode(kap, encrypted_data)
        if decrypted_data[:RANDOM_BYTES] == self.update_info["random"]:
            # logger.info("update the credential successfully")
            # update salt
            new_salt = str(decrypted_data[RANDOM_BYTES:], encoding=MY_ENCODING)  # str
            update_salt(self.update_info["device_id"], new_salt)
            devices_salt[self.update_info["device_id"]] = new_salt
            # self.update_info = {}


class AppDifferentASClientFactory(protocol.ClientFactory):
    protocol = AppDifferentASClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class AppDifferentRSClient(protocol.Protocol):
    def __init__(self):
        self.different_device_id = different_device_id
        self.krp = different_info[self.different_device_id]["krp"]
        self.rs_id = different_info[self.different_device_id]["rs_id"]
        self.connection_data = different_info[self.different_device_id]["connection_data"]
        self.switch = {
            707: self.different708,
            715: self.different716
        }

    def connectionMade(self):
        logger.info('communication_bytes:%s' % (len(self.connection_data.encode(MY_ENCODING))))
        self.transport.write(self.connection_data.encode(MY_ENCODING))  # connects with RS
        logger.info("app sends 给RS:%s" % self.connection_data)

    def dataReceived(self, raw_data):
        rec_data = raw_data.decode(MY_ENCODING)
        logger.info('app receives from RS:' + rec_data)
        start_time = time.time_ns()
        code = json.loads(rec_data)["message"]["code"]
        send_data = self.switch[code](rec_data)
        end_time = time.time_ns()
        logger.info('time:%s app sends to RS: %s' % (end_time-start_time, send_data))
        if send_data:
            logger.info('communication_bytes:%s app sends to RS: %s' % (len(send_data.encode(MY_ENCODING)), send_data))
            self.transport.write(send_data.encode(MY_ENCODING))

    def connectionLost(self, reason):
        logger.info('the server is closed')

    def different708(self, rec_data):
        logger.info('connects with RS successfully, then sends a message to RS')
        return self.different712()

    def different712(self):
        for i in range(LOOP_TIMES):
            data = b'M3'
            encrypted_data = aes_encode(self.krp, data)
            message = {
                "code": 712,
                "time": int(time.time()),
                "rs_id": str(b64encode(self.rs_id), encoding=MY_ENCODING),
                "encrypted_data": encrypted_data
            }
            hmac = hmac_md5(self.krp, json.dumps(message))
            send_json = {
                "message": message,
                "hmac": hmac
            }
            send_data = json.dumps(send_json)
        return send_data

    def different716(self, rec_data):
        for i in range(LOOP_TIMES):
            rec_message, rec_hmac = resolve_message_hmac(rec_data)
            if int(time.time()) - rec_message["time"] <= DELTA_TIME and hmac_md5(self.krp, json.dumps(rec_message)) == rec_hmac:
                encrypted_data = rec_message["encrypted_data"]
                decrypted_data = aes_decode(self.krp, encrypted_data)
                # logger.info(" receives a message from RS: %s" % decrypted_data)
                # return self.different712()  # keep sending messages


class AppDifferentRSClientFactory(protocol.ClientFactory):
    protocol = AppDifferentRSClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


def main():
    mode = input("Please choose the mode, 1:bind 2:communication in LAN 3:communication in public network 4:update the credential ")
    if mode == '1':
        reactor.connectTCP(DEVICE_BIND_TCP_SERVER_HOST, DEVICE_BIND_TCP_SERVER_PORT, AppBindClientFactory())
    elif mode == '2':
        reactor.listenUDP(0, EchoClientDatagramProtocol())
    elif mode == '3':
        reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())
    elif mode == '4':
        global update_mode
        update_mode = True
        reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())
    reactor.run()


if __name__ == '__main__':
    main()

import os
import time
cur_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.abspath(os.path.join(cur_dir, os.pardir))
import sys
sys.path.append(parent_dir)

import signal
from select import select
from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
from enum import IntEnum
import logging
from logging.handlers import RotatingFileHandler
from messages import *
import time
import threading
from sys import platform
from queue import Queue
import queue

TCP_RECV_RX_BUFFER_LEN = 1024
log = logging.getLogger("DoIP-SERVER")
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(filename)s:%(funcName)s():%(lineno)d] [%(levelname)s] [%(thread)d] - %(message)s")
default_handler = logging.StreamHandler()
handler = RotatingFileHandler(filename=".\\log\\doip\\doip_server.log", maxBytes=5 * 1024 * 1024, backupCount=2)
log.addHandler(default_handler)
log.addHandler(handler)     
handler.setFormatter(formatter)
default_handler.setFormatter(formatter)

log.info("DoIP SERVER LOG init.")
log.info("PLATFORM: {}".format(platform))


G_P2_SERVER = 0x32
G_P2STAR_SERVER = 0x07D0

def signal_handler(signum, frame):
    log.info("SIGINT triggered.")
    log.info("signal: {}, frame: {}".format(signal.strsignal(signum), frame))
    log.info("going to exit!")
    exit(0)


class UDSState(IntEnum):
    IDLE = 0
    REQUEST_RECEIVED = 1
    PENDING = 2
    POSITIVE_RESPONSE = 3
    NEGATIVE_RESPONSE = 4


class NRC(IntEnum):
    DEFAULT_OK = 0x00
    SUB_FUNC_NOT_SUPPORT = 0x12
    REQUEST_OUT_OF_RANGE = 0x31
    KEY_INVALID = 0x35
    PENDING = 0x78


class ParserState(IntEnum):
    READ_PROTOCOL_VERSION = 1
    READ_INVERSE_PROTOCOL_VERSION = 2
    READ_PAYLOAD_TYPE = 3
    READ_PAYLOAD_LENGTH = 4
    READ_PAYLOAD_OPEN = 5
    READ_PAYLOAD_DONE = 6
    

class Parser:
    def __init__(self):
        self.reset()

    def reset(self):
        self.rx_buffer = bytearray()
        self.protocol_version = 0x00
        self.inverse_version = 0x00
        self.payload_type = 0x0000
        self.payload_length = 0x00000000
        self.payload = bytearray()
        self._state = ParserState.READ_PROTOCOL_VERSION

    def parse(self, data):
        self.rx_buffer += data
        log.debug("parser buffer: 0x{}".format(self.rx_buffer.hex().upper()[:64]))
        parsed_list = []

        while len(self.rx_buffer) > 0:
            if self._state == ParserState.READ_PROTOCOL_VERSION:
                self.payload = bytearray()
                if len(self.rx_buffer) >= 1:
                    self.protocol_version = int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_INVERSE_PROTOCOL_VERSION
                else:
                    break
                
            if self._state == ParserState.READ_INVERSE_PROTOCOL_VERSION:
                if len(self.rx_buffer) >= 1:
                    self.inverse_version = int(self.rx_buffer.pop(0))
                    if self.inverse_version != (0xFF ^ self.protocol_version):
                        log.warning("DoIP HEADER: protocol version && inverse version CAN NOT match. Ignoring......")
                    self._state = ParserState.READ_PAYLOAD_TYPE
                else:
                    break
            
            if self._state == ParserState.READ_PAYLOAD_TYPE:
                if len(self.rx_buffer) >= 2:
                    self.payload_type = int(self.rx_buffer.pop(0)) << 8
                    self.payload_type |= int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_PAYLOAD_LENGTH
                else:
                    break
            
            if self._state == ParserState.READ_PAYLOAD_LENGTH:
                if len(self.rx_buffer) >= 4:
                    self.payload_length = int(self.rx_buffer.pop(0)) << 24
                    self.payload_length |= int(self.rx_buffer.pop(0)) << 16
                    self.payload_length |= int(self.rx_buffer.pop(0)) << 8
                    self.payload_length |= int(self.rx_buffer.pop(0))
                    self._state = ParserState.READ_PAYLOAD_OPEN
                else:
                    break

            if self._state == ParserState.READ_PAYLOAD_OPEN:
                if len(self.rx_buffer) < self.payload_length:
                    log.info("Current parser wants more data......")
                    break
                else:
                    self.payload += self.rx_buffer[:self.payload_length]
                    self.rx_buffer = self.rx_buffer[self.payload_length:]
                    self._state = ParserState.READ_PROTOCOL_VERSION
                    log.debug("payload_type: {}".format(payload_type_to_message_dict[self.payload_type]))
                    log.debug("After parse, payload: 0x{}".format(self.payload.hex().upper()[:64]))
                    parsed_list.append(payload_type_to_message_dict[self.payload_type].unpack(self.payload, self.payload_length))
        
        return parsed_list

class DoIPServer(threading.Thread):
    def __init__(
        self,
        self_logical_address = 0x0002,
        tcp_port = 13400,
        udp_port = 13400,
        activation_type = 0x00,
        protocol_version = 0x02,
        ip_address = "127.0.0.1",
    ):
        # TODO: Make all the info to be property!
        self._self_logical_address = self_logical_address
        self._tcp_port = tcp_port
        self._udp_port = udp_port
        self._activation_type = activation_type
        self._tcp_parser = Parser()
        self._protocol_version = protocol_version
        self._ip_address = ip_address
        self._tcp_close_detected = False
        self._listen_tcp_sock = socket(AF_INET, SOCK_STREAM)
        self._is_routing_activated = False
        self._client_sockfd = None
        self._client_logical_address = None
        self._is_running = True
        self._write_queue = Queue()

        self._listen_tcp_sock.setblocking(False)
        self._listen_tcp_sock.bind((self._ip_address, self._tcp_port))

        # UDS stuff
        self._current_session = 0x01
        self._uds_state = UDSState.IDLE
        self._security_unlocked = False

        self._driver_data_file_handler = None
        self._app_data_file_handler = None
        self._driver_data_file_handler = open(".\\driver.data", "wb+")
        self._app_data_file_handler = open(".\\app.data", "wb+")
        self._current_transfer_file_type = 0 # 0: driver; 1: app. just for quick realisation
        super().__init__()
    
    def uds_handler(self, b_uds_request):
        nrc = NRC.DEFAULT_OK
        b_uds_response = b""
        service_id = b_uds_request[0]
        service_payload = b_uds_request[1:]
        log.info(f"uds request: 0x{b_uds_request.hex().upper()[:64]}")
        if service_id == 0x10:
            if service_payload == bytearray.fromhex("01"):
                b_uds_response = bytearray.fromhex("5001")
            elif service_payload == bytearray.fromhex("02"):
                b_uds_response = bytearray.fromhex("5002")
            elif service_payload == bytearray.fromhex("03"):
                b_uds_response = bytearray.fromhex("5003")
            else:
                log.error("Unknown session control ID!")
        elif service_id == 0x11:
            b_uds_response = bytearray.fromhex("5101")
        elif service_id == 0x14:
            b_uds_response = bytearray.fromhex("54")
        elif service_id == 0x22:
            if service_payload == bytearray.fromhex("F195"):
                b_uds_response = bytearray.fromhex("62F195") + bytearray(b"Linux 0.11")
            elif service_payload == bytearray.fromhex("F187"):
                b_uds_response = bytearray.fromhex("62F187") + bytearray(b"RTFSC")
            else:
                nrc = NRC.REQUEST_OUT_OF_RANGE
                b_uds_response = bytearray.fromhex("7F2231")
        elif service_id == 0x27:
            if service_payload == bytearray.fromhex("11"):
                b_uds_response = bytearray.fromhex("6711") +  bytearray(b"sesame")
            elif service_payload[0] == 0x12:
                if service_payload[1:] == bytearray(b"open sesame"):
                    self._security_unlocked = True
                    b_uds_response = bytearray.fromhex("6712")
                else:
                    nrc = NRC.KEY_INVALID
                    b_uds_response = bytearray.fromhex("7F2735")
            else:
                nrc = NRC.REQUEST_OUT_OF_RANGE
                b_uds_response = bytearray.fromhex("7F2731")
        elif service_id == 0x28:
            b_uds_response = bytearray.fromhex("6803")
        elif service_id == 0x2E:
            # NOTE: only simulate 2EF184
            b_uds_response = bytearray.fromhex("6EF184")
        elif service_id == 0x31:
            # NOTE: All routine of 31 are defined by different OEMs, below are just demonstration
            if service_payload == bytearray.fromhex("010203"):
                b_uds_response = bytearray.fromhex("7101010203")
            elif service_payload[:3] == bytearray.fromhex("010202"):
                if service_payload[3:] == bytearray(b"fuck crc"):
                    b_uds_response = bytearray.fromhex("710101020200")
                else:
                    b_uds_response = bytearray.fromhex("7F3131")
            elif service_payload[:4] == bytearray.fromhex("01FF0011"):
                self._current_transfer_file_type = 1
                b_uds_response = bytearray.fromhex("7101FF0011")
            elif service_payload[:3] == bytearray.fromhex("01FF00"):
                b_uds_response = bytearray.fromhex("7101ff0100")
            else:
                b_uds_response = bytearray.fromhex("71")
        elif service_id == 0x34:
            b_uds_response = bytearray.fromhex("744000300002")
        elif service_id == 0x36:
            # NOTE: might block for real-time processing
            if self._current_transfer_file_type == 0:
                self._driver_data_file_handler.write(service_payload[1:])
            else:
                self._app_data_file_handler.write(service_payload[1:])
            log.debug(f"{service_payload[:2]}")
            b_uds_response = bytearray.fromhex("76") + service_payload[:1]
        elif service_id == 0x37:
            b_uds_response = bytearray.fromhex("77")
        elif service_id == 0x3E:
            # NOTE: just for 3E80
            pass
        elif service_id == 0x85:
            b_uds_response = bytearray.fromhex("C502")
        else:
            log.info("Unknown UDS request")
        
        return nrc, b_uds_response

    def run(self):
        log.info("Server start......")
        self._listen_tcp_sock.listen(1)
        
        select_sock_list = [self._listen_tcp_sock]

        while self._is_running:
            r_sock_list, w_sock_list, e_sock_list = select(select_sock_list, select_sock_list, select_sock_list)

            for sockfd in r_sock_list:
                if sockfd == self._listen_tcp_sock:
                    self._client_sockfd, client_address = self._listen_tcp_sock.accept()
                    log.info("New client accept: {}".format(client_address))
                    self._client_sockfd.setblocking(False)
                    select_sock_list.append(self._client_sockfd)
                elif sockfd == self._client_sockfd:
                    b_request = b""
                    while True:
                        try:
                            b_request = b_request + sockfd.recv(TCP_RECV_RX_BUFFER_LEN)
                        except BlockingIOError:
                            log.info("Would Block triggered, next time we read.")
                            break
                        except Exception as reason:
                            log.error("Something wrong with data recv, Exception: {}".format(reason))
                            self._is_running = False
                            break
                    # REAL parse starts here!
                    log.debug("b_request: 0x{}".format(b_request.hex()[:64]))
                    response_list = list()
                    if len(b_request) > 0:
                        response_list = self._tcp_parser.parse(b_request)
                        log.debug("After parse......")
                    for response in response_list:
                        if type(response) == RoutingActivationRequest:
                            log.info("Receive routing activate request.")
                            self._client_logical_address = response.source_address
                            ra_resopnse = RoutingActivationResponse(client_logical_address=self._client_logical_address, logical_address=self._self_logical_address)
                            self._write_queue.put(ra_resopnse)
                            # self._is_routing_activated = True
                        elif type(response) == DiagnosticMessage:
                            if self._is_routing_activated:
                                # log.info(f"Source address: 0x{response.source_address:04X}")
                                nrc, b_uds_response = self.uds_handler(response.user_data)
                                diag_response = DiagnosticMessage(source_address=self._self_logical_address, target_address=response.source_address, user_data=b_uds_response)
                                # Actually, you need to do some checkings here to decide whether to send ACK/NACK
                                diag_ack = DiagnosticMessagePositiveAcknowledgement(source_address=self._self_logical_address, target_address=response.source_address)
                                self._write_queue.put(diag_ack)
                                self._write_queue.put(diag_response)
                            else:
                                log.info("Received Diagnostic Message, but not routing activated, just IGNORE")
                                pass
                        else:
                            log.warning("Now only support routing activation request && diagnostic message, just ignore......")

            for sockfd in w_sock_list:
                if sockfd == self._client_sockfd:
                    try:
                        message = self._write_queue.get_nowait()
                        log.info("About to send message type: {}".format(type(message).__name__))
                        log.info("Send to: " + self._client_sockfd.getpeername()[0] + ", 0x" + bytes.hex(message.pack()).upper()[:32])
                        self._client_sockfd.send(message.pack())
                        if type(message) == RoutingActivationResponse:
                            log.info("message is RA response, set activation flag")
                            self._is_routing_activated = True
                    except queue.Empty:
                        # log.warning("Queue empty")
                        pass
                    except Exception as reason:
                        log.error("Something wrong with data send, Exception: {}".format(reason))
                        self._is_running = False
                else:
                    log.info("Who's your daddy?")
            
            for sockfd in e_sock_list:
                log.error("ERROR socket fd: {}".format(sockfd))

        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    server = DoIPServer()
    server.daemon = True
    server._is_running = True
    server.start()

    while server._is_running:
        log.info("Server is running.")
        time.sleep(10)
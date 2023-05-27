import os
import time
cur_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.abspath(os.path.join(cur_dir, os.pardir))
import sys
sys.path.append(parent_dir)

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

class UDSState(IntEnum):
    IDLE = 0
    SENT = 1
    PENDING = 2
    POSITIVE_RESPONSE = 3
    NEGATIVE_RESPONSE = 4
    FUNCTIONAL_COLLECTING = 5

TCP_RECV_RX_BUFFER_LEN = 1024
log = logging.getLogger("DoIP-STACK")
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(filename)s:%(funcName)s():%(lineno)d] [%(levelname)s] [%(thread)d] - %(message)s")
default_handler = logging.StreamHandler()
handler = RotatingFileHandler(filename=".\\log\\doip\\doip_stack.log", maxBytes=5 * 1024 * 1024, backupCount=2)
log.addHandler(default_handler)
log.addHandler(handler)     
handler.setFormatter(formatter)
default_handler.setFormatter(formatter)

log.info("DoIP STACK LOG init.")
log.info("PLATFORM: {}".format(platform))


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
        log.debug("parser buffer: 0x{}".format(self.rx_buffer.hex().upper()))
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
                    log.debug("After parse, payload: 0x{}".format(self.payload.hex().upper()))
                    parsed_list.append(payload_type_to_message_dict[self.payload_type].unpack(self.payload, self.payload_length))
        
        return parsed_list

class DoIPNode():

    def __init__(self):
        pass
        

class DoIPStack(threading.Thread):
    """_summary_

    Args:
        threading (_type_): _description_
    """

    def __init__(
        self,
        ecu_logical_address = 0xABCD,
        tcp_port = 13400,
        udp_port = 13400,
        activation_type = 0x00,
        protocol_version = 0x02,
        client_ip_address = "127.0.0.1",
        client_logical_address = 0xDCBA,
        server_ip_address = "127.0.0.1",
        client_dict = dict()
    ):
        # TODO: Make all the info to be property!
        self._ecu_logical_address = ecu_logical_address
        self._client_logical_address = client_logical_address
        self._client_ip_address = client_ip_address
        self._tcp_port = tcp_port
        self._udp_port = udp_port
        self._activation_type = activation_type
        self._tcp_parser = Parser()
        self._protocol_version = protocol_version
        self._server_ip_address = server_ip_address
        self._tcp_close_detected = False
        self._local_edge_node_tcp_sock = socket(AF_INET, SOCK_STREAM)
        self._tx_uds_message_queue = Queue()
        self._is_edge_node_connected = False
        self._is_routing_activated = False
        self._master_client = None
        self._client_dict = client_dict

        self._local_edge_node_tcp_sock.bind((self._client_ip_address, 0))
        self._local_edge_node_tcp_sock.setblocking(False)

        super().__init__()
    
    def register_client(self, logic_addr, client):
        self._client_dict[logic_addr] = client
        client._doip_send = self.doip_send
        
    def deregister_client(self, logic_addr):
        client = self._client_dict.pop(logic_addr)
        log.info("client removed from stack: {}".format(client))
        return client

    def register_master_client(self, logic_addr, client):
        self.register_client(logic_addr=logic_addr, client=client)
        self._master_client = client
    
    # NOTE: tx_uds_message_queue is PUBLIC resource && this Queue() obj is thread-safe.
    def doip_send(self, message):
        self._tx_uds_message_queue.put(message)

    def connect_edge_node(self, timeout):
        rc = self._local_edge_node_tcp_sock.connect_ex((self._server_ip_address, self._tcp_port))
        if rc == 0:
            log.info("EDGE NODE connected!")
            return 0
        # NOTE: 10035, same meaning as EAGAIN/EWOULDBLOCK in Linux
        elif rc != 10035:
            log.error("EDGE NODE connect ERROR, RC: " + str(rc))
            return rc
        local_list = [self._local_edge_node_tcp_sock, ]
        r_list, w_list, e_list = select(local_list, local_list, local_list, timeout)
        if len(w_list) == 0:
            log.info("no event found on local EDGE NODE connect sock until timeout: {}s".format(timeout))
            return -1
        for fd in w_list:
            log.info("EDGE NODE connected, ip: " + fd.getpeername()[0])
        for fd in r_list:
            log.info("r_list OK, peer: " + fd.getpeername()[0])
        for fd in e_list:
            log.error("e_list OK, peer: " + fd.getpeername()[0])
            return -1
    
        return 0
    
    def routing_activate_edge_node(self):
        if self._is_routing_activated == True:
            return
        ra = RoutingActivationRequest(source_address=self._client_logical_address)
        self.doip_send(ra)
        log.info("Routing activation of edge node SENT")
    
    def write_thread_entry(self):
        while self._is_edge_node_connected:
            while self._tx_uds_message_queue.not_empty:
                message = self._tx_uds_message_queue.get()
                try:
                    log.info("About to send message type: {}".format(type(message).__name__))
                    log.info("Send to: " + self._local_edge_node_tcp_sock.getpeername()[0] + ", 0x" + bytes.hex(message.pack()).upper()[:32])
                    self._local_edge_node_tcp_sock.send(message.pack())
                except Exception as reason:
                    log.error("Something wrong with data send, Exception: {}".format(reason))
                    self._is_edge_node_connected = False
                    break
        log.info("Current writing thread of edge node exit......")
    
    def read_thread_entry(self):
        local_sock_list = [self._local_edge_node_tcp_sock, ]
        while self._is_edge_node_connected:
            r_sock_list, w_sock_list, e_sock_list = select(local_sock_list, local_sock_list, local_sock_list)
            if self._local_edge_node_tcp_sock in e_sock_list:
                self._is_edge_node_connected = False
                log.debug("error list tick")
                log.error("ERROR occured, peer: " + self._local_edge_node_tcp_sock.getpeername()[0])
                break
            if self._local_edge_node_tcp_sock in r_sock_list:
                log.debug("read list tick")
                b_response = b""
                while True:
                    try:
                        b_response = b_response + self._local_edge_node_tcp_sock.recv(TCP_RECV_RX_BUFFER_LEN)
                    except BlockingIOError:
                        log.info("Would Block triggered, next time we read.")
                        break
                    except Exception as reason:
                        log.error("Something wrong with data recv, Exception: {}".format(reason))
                        self._is_edge_node_connected = False
                        break
                # REAL parse starts here!
                response_list = self._tcp_parser.parse(b_response)
                log.debug("After parse......")
                for response in response_list:
                    if type(response) == RoutingActivationResponse:
                        log.debug("Calling routing request callback......")
                        if response.response_code == 0x10:
                            self._is_routing_activated = True
                        self._master_client.routing_activate_edge_node_callback(response)
                        log.debug("Called routing request callback......")
                    elif type(response) == DiagnosticMessage:
                        log.debug("Before calling doip_send_callback")
                        log.info(f"Source address: 0x{response.source_address:04X}")
                        try:
                            self._client_dict[response.source_address].doip_send_callback(response)
                        except:
                            log.warning(f"No ECU: {response.source_address:04X}, or the client is not registered!")
                        log.debug("After calling doip_send_callback")
    
        log.info("Current reading thread of edge node exit......")

    def run(self):        
        write_thread = threading.Thread(target=self.write_thread_entry, args=())
        write_thread.daemon = True
        write_thread.start()

        read_thread = threading.Thread(target=self.read_thread_entry, args=())
        read_thread.daemon = True
        read_thread.start()

        while self._is_edge_node_connected:
            log.info("Stack is running.")
            time.sleep(10)
        
        log.info("Stack exit...")
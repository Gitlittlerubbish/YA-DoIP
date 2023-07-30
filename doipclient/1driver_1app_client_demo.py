import os
import time
cur_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.abspath(os.path.join(cur_dir, os.pardir))
import sys
sys.path.append(parent_dir)

from enum import IntEnum
import logging
from logging.handlers import RotatingFileHandler
from messages import *
import time
import threading
from threading import Timer
from sys import platform

from stack import DoIPStack
import hexrec.records as hr
from ctypes import *
import signal

log = logging.getLogger("DoIP-CLIENT-APA")
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(filename)s:%(funcName)s():%(lineno)d] [%(levelname)s] [%(thread)d] - %(message)s")
default_handler = logging.StreamHandler()
handler = RotatingFileHandler(filename=".\\log\\doip\\doip_client_demo.log", maxBytes=5 * 1024 * 1024, backupCount=2)
log.addHandler(handler)
log.addHandler(default_handler)
handler.setFormatter(formatter)
default_handler.setFormatter(formatter)

log.info("DoIP CLIENT-DEMO LOG init.")
log.info("PLATFORM: {}".format(platform))

def signal_handler(signum, frame):
    log.info("SIGINT triggered.")
    log.info("signal: {}, frame: {}".format(signal.strsignal(signum), frame))
    log.info("going to exit!")
    exit(0)

class UDSState(IntEnum):
    IDLE = 0
    SENT = 1
    PENDING = 2
    POSITIVE_RESPONSE = 3
    NEGATIVE_RESPONSE = 4
    FUNCTIONAL_COLLECTING = 5


class FlashState(IntEnum):
    IDLE = 0
    EDGE_NODE_ROUTING_ACTIVATE = 1
    # pre-programming
    F_PRE_PROGRAMMING_EXTENDED_SESSION_ON = 2 # 1003
    P_CHECK_PROGRAMMING_PRECONDITIONS = 3 # 31010203
    F_CONTROL_DTC_OFF = 4 # 8502
    F_COMMUNICATION_CONTROL_OFF = 5 # 280301
    # programming
    P_PROGRAMMING_SESSION_ON = 6 # 1002
    P_REQUEST_SECURITY_ACCESS_GET_KEY = 7 # 2711
    P_REQUEST_SECURITY_ACCESS_SEND_SEED = 8 # 2712
    P_WRITE_WHAT_THE_HELL = 9 #2EF184
    P_DRIVER_REQUEST_DOWNLOAD = 10 # 34
    P_DRIVER_REQUEST_TRANSFER_DATA = 11 # 36 X N
    P_DRIVER_REQUEST_TRANSFER_EXIT = 12 # 37
    P_DRIVER_CHECK_MEMORY_INTEGRITY = 13 # 31010202 + CRC
    P_TELL_DADDY_MEMORY_ADDRESS = 14 # 3101FF0011 + ADDR + SIZE
    P_APP_REQUEST_DOWNLOAD = 15 # 34
    P_APP_REQUEST_TRANSFER_DATA = 16 # 36 X N
    P_APP_REQUEST_TRANSFER_EXIT = 17 # 37
    P_APP_CHECK_MEMORY_INTEGRITY = 18 # 31010202 + CRC
    P_CHECK_PROGRAMMING_DEPENDENCY = 19 # 3101FF00
    #post-programming
    P_REQUEST_ECU_RESET = 20 # 1101
    F_POST_PROGRAMMING_EXTENDED_SESSION_SWITCH = 21 # 1003
    F_COMMUNICATION_CONTROL_ON = 22 # 280001
    F_CONTROL_DTC_ON = 23 # 8501
    F_DEFAULT_SESSION_ON = 24 # 1001
    F_CLEAR_DIAGNOSTIC_INFORMATION = 25 # 14FFFFFF
    # over
    FLASHED_OK = 26
    FLASHED_FAIL =27


class EcuBlock():

    _memory_address = 0x00000000
    _memory_size = 0x00000000
    _binary_content = bytearray()
    def __init__(self, memory_address, memory_size, binary_content):
        self._memory_address = memory_address
        self._memory_size = memory_size
        self._binary_content = binary_content


class DoIPClient(threading.Thread):

    def __init__(self, doip_stack=None, id=0, target_address=0x0002, doip_send=None, rx_message_list=[]):
        self._doip_stack = doip_stack
        self._id = id
        self._target_address = target_address
        self._flash_state = FlashState.IDLE
        self._uds_state = UDSState.IDLE
        self._current_client_running = False
        self._current_uds_service = 0x00
        self._current_uds_payload = 0x00
        self._doip_send = doip_send
        self.generate_key = None
        self._driver_path = ".\\demo\\driver.txt"
        self._app_path = ".\\demo\\app.txt"
        self._driver_blocks = list()
        self._current_driver_block_index = 0
        self._app_blocks = list()
        self._current_app_block_index = 0
        self._app_block_number = 1
        self._current_to_send_block_raw_data = 0x00
        self._seg_size = 0x00
        self._block_len_max = 0x00
        self._block_sequence_counter = 1
        self._data_buf_len = 0
        self._uds_event = threading.Event()
        
        super().__init__()

    def process_software_package(self):
        # try:
        log.info("Processing DRIVER......")
        driver_fp = open(self._driver_path, "rb")
        driver_buf = driver_fp.read()
        log.debug(f"{len(driver_buf)}")
        log.debug(f"{driver_buf}")
        # NOTE: address, size of binary buffer, binary buffer
        self._driver_blocks.append(["00000000", "0000037E", driver_buf])

        log.info("Processing APP......")
        app_fp = open(self._app_path, "rb")
        app_buf = app_fp.read()
        log.debug(f"{len(app_buf):X}")
        log.debug(f"{app_buf[:30]}")
        # NOTE: address, size of binary buffer, binary buffer
        self._app_blocks.append(["00000000", "0A824812", app_buf])

        return 0
        # except:
        #     return -1

    def routing_activate_edge_node(self):
        self._doip_stack.routing_activate_edge_node()
        
    def routing_activate_edge_node_callback(self, response):
        if response.response_code == 0x10:
            self._flash_state = FlashState.EDGE_NODE_ROUTING_ACTIVATE
            log.info("Current node routing activated.")
        else:
            self._current_client_running = False
            log.info("Current node routing activation failed, code: 0x{}".format(response.response_code))
        log.info("I am the routing activation callback of edge node.")
        self._uds_event.set()

    def doip_send_callback(self, message):
        log.info(f"0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data[:24].hex().upper()}")
        if self._uds_state == UDSState.FUNCTIONAL_COLLECTING:
            log.info("Functional response collecting......")
            return
        elif self._uds_state == UDSState.SENT or self._uds_state == UDSState.PENDING:
            if message.user_data[0] == 0x7F:
                if message.user_data[2] == 0x78:
                    self._uds_state = UDSState.PENDING
                    log.info("pending.......")
                    self._uds_event.set()
                    return
                else:
                    self._uds_state = UDSState.NEGATIVE_RESPONSE
                    log.info("negative......")
                    self._uds_event.set()
                    return
            elif message.user_data[0] == self._current_uds_service + 0x40:
                self._uds_state = UDSState.POSITIVE_RESPONSE
                self._current_uds_payload = message.user_data[2:]
                log.info(f"Current uds payload: 0x{self._current_uds_payload.hex().zfill(8)}")
                log.info("positive......")
                self._uds_event.set()
                return
            else:
                self._uds_state = UDSState.NEGATIVE_RESPONSE
                log.error("Unkown UDS service, not match!!!!!!")
                self._uds_event.set()
                return
        else:
            log.error("Unkown UDS state!!!!!! Current UDS state: {}".format(self._uds_state))
            self._uds_state = UDSState.NEGATIVE_RESPONSE
            self._uds_event.set()
            return         

    def run(self):
        log.info("DoIP CLIENT No.{} START".format(self._id))
        log.info("Start processing APA software package......")
        
        self.routing_activate_edge_node()
        self._current_client_running = True
        while self._current_client_running:
            self._uds_event.wait(timeout=5.0)
            log.info("I am here")
            self.process()
            self._uds_event.clear()
        
        log.info("Current client exit......")

    # This function for UDS flow control
    def process(self):
        log.info(f"Flash state: {self._flash_state.name}")
        if self._flash_state == FlashState.EDGE_NODE_ROUTING_ACTIVATE:
            self._flash_state = FlashState.F_PRE_PROGRAMMING_EXTENDED_SESSION_ON
        
        # pre-programming starts!
        if self._flash_state == FlashState.F_PRE_PROGRAMMING_EXTENDED_SESSION_ON:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("1003"))
            self._doip_send(message)
            self._current_uds_service = 0x10
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.P_CHECK_PROGRAMMING_PRECONDITIONS
        
        if self._flash_state == FlashState.P_CHECK_PROGRAMMING_PRECONDITIONS:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("31010203"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x31
                log.info(f"{type(message)} 0x{message.source_address:04X} -> 0x{message.target_address:04X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.F_CONTROL_DTC_OFF
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return

        if self._flash_state == FlashState.F_CONTROL_DTC_OFF:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("8502"))
            self._doip_send(message)
            self._current_uds_service = 0x85
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.F_COMMUNICATION_CONTROL_OFF

        if self._flash_state == FlashState.F_COMMUNICATION_CONTROL_OFF:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("280301"))
            self._doip_send(message)
            self._current_uds_service = 0x28
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.P_PROGRAMMING_SESSION_ON

        # programming starts!!!
        if self._flash_state == FlashState.P_PROGRAMMING_SESSION_ON:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("1002"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x10
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_REQUEST_SECURITY_ACCESS_GET_KEY
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return

        if self._flash_state == FlashState.P_REQUEST_SECURITY_ACCESS_GET_KEY:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("2711"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x27
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_REQUEST_SECURITY_ACCESS_SEND_SEED
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return

        if self._flash_state == FlashState.P_REQUEST_SECURITY_ACCESS_SEND_SEED:
            if self._uds_state == UDSState.IDLE:
                log.info("hello " + self._current_uds_payload.hex().zfill(8))
                seed = bytes.fromhex(self._current_uds_payload.hex().zfill(8))
                log.info(f"2711 seed: {seed.hex()}")
                key = bytes.fromhex("".zfill(32))
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("2712") + bytearray(b"open sesame"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x27
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_WRITE_WHAT_THE_HELL
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return

        if self._flash_state == FlashState.P_WRITE_WHAT_THE_HELL:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("2EF184" + "2307300123456789AB"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x2E
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_DRIVER_REQUEST_DOWNLOAD
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return
        
        if self._flash_state == FlashState.P_DRIVER_REQUEST_DOWNLOAD:
            current_block = self._driver_blocks[self._current_driver_block_index]
            log.info(f"Processing driver block: {current_block[:32]}")
            addr_hex = current_block[0]
            len_hex = current_block[1]
            self._current_to_send_block_raw_data = current_block[2]
            if self._uds_state == UDSState.IDLE:
                hex_payload = "340044" + addr_hex + len_hex
                log.info(f"Raw 34 service hex: 0x{hex_payload}")
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex(hex_payload))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x34
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                self._seg_size = int(len_hex, base=16)
                self._block_sequence_counter = 1
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._block_len_max = int.from_bytes(self._current_uds_payload, 'big', signed=False) - 2
                log.info(f"Max block length: 0x{self._block_len_max:X}")
                self._flash_state = FlashState.P_DRIVER_REQUEST_TRANSFER_DATA
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return    
        
        if self._flash_state == FlashState.P_DRIVER_REQUEST_TRANSFER_DATA:
            current_block = self._driver_blocks[self._current_driver_block_index]
            if self._uds_state == UDSState.IDLE or self._uds_state == UDSState.POSITIVE_RESPONSE:
                if self._seg_size > 0:
                    log.debug(f"Current remaining segment size: 0x{self._seg_size:X}")
                    if self._seg_size > self._block_len_max:
                        data_buf_len = self._block_len_max
                    else:
                        data_buf_len = self._seg_size
                    data_buf = self._current_to_send_block_raw_data[:data_buf_len]
                    self._current_to_send_block_raw_data = self._current_to_send_block_raw_data[data_buf_len:]
                    if self._block_sequence_counter == 256:
                        self._block_sequence_counter = 0
                    user_data_prefix = bytes.fromhex("36" + hex(self._block_sequence_counter)[2:].zfill(2))
                    self._current_uds_service = 0x36
                    message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=user_data_prefix + data_buf)
                    log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                    self._uds_state = UDSState.SENT
                    self._doip_send(message)
                    self._block_sequence_counter += 1
                    self._seg_size -= data_buf_len
                    return
                else:
                    self._uds_state = UDSState.IDLE
                    self._flash_state = FlashState.P_DRIVER_REQUEST_TRANSFER_EXIT
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return    
        
        if self._flash_state == FlashState.P_DRIVER_REQUEST_TRANSFER_EXIT:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("37"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x37
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                if self._current_driver_block_index < len(self._driver_blocks) -1:
                    self._current_driver_block_index += 1
                    self._flash_state = FlashState.P_DRIVER_REQUEST_DOWNLOAD
                else:
                    self._flash_state = FlashState.P_DRIVER_CHECK_MEMORY_INTEGRITY
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return    

        if self._flash_state == FlashState.P_DRIVER_CHECK_MEMORY_INTEGRITY:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("31010202") + bytearray(b"fuck crc"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x31
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_TELL_DADDY_MEMORY_ADDRESS
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return    

        if self._flash_state == FlashState.P_TELL_DADDY_MEMORY_ADDRESS:
            if self._uds_state == UDSState.IDLE:
                # NOTE: HARD coded, address + size
                raw_hex_payload = "3101FF0011" + "00000000" + "60152693"
                log.info("Raw hex payload: 0x" + raw_hex_payload)
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex(raw_hex_payload))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x31
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_APP_REQUEST_DOWNLOAD
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return

        if self._flash_state == FlashState.P_APP_REQUEST_DOWNLOAD:
            if self._current_app_block_index >= self._app_block_number:
                log.info("App blocks all transfered.")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_APP_CHECK_MEMORY_INTEGRITY
            else:
                log.info(f"Current process app block_{self._current_app_block_index} 34 36 37")
                current_block = self._app_blocks[self._current_app_block_index]
                addr_hex = current_block[0]
                len_hex = current_block[1]
                self._current_to_send_block_raw_data = current_block[2]
                if self._uds_state == UDSState.IDLE:
                    raw_hex_payload = "340044" + addr_hex + len_hex
                    log.info("Raw hex payload: 0x" + raw_hex_payload)
                    message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex(raw_hex_payload))
                    self._uds_state = UDSState.SENT
                    self._doip_send(message)
                    self._current_uds_service = 0x34
                    log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                    self._seg_size = int(len_hex, base=16)
                    self._block_sequence_counter = 1
                    return
                elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                    log.info(f"0x{self._current_uds_service:X} positive")
                    self._block_len_max = int.from_bytes(self._current_uds_payload, 'big', signed=False) - 2
                    log.info(f"Max block length: 0x{self._block_len_max:X}")
                    self._uds_state = UDSState.IDLE
                    self._flash_state = FlashState.P_APP_REQUEST_TRANSFER_DATA
                elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                    log.error(f"0x{self._current_uds_service:X} negative")
                    self._current_client_running = False
                    return
                elif self._uds_state == UDSState.PENDING:
                    log.info(f"0x{self._current_uds_service:X} pending")
                    return
                else:
                    log.error("You should not get here!!!")
                    self._current_client_running = False
                    return
        
        if self._flash_state == FlashState.P_APP_REQUEST_TRANSFER_DATA:
            if self._uds_state == UDSState.IDLE or self._uds_state == UDSState.POSITIVE_RESPONSE:
                if self._seg_size > 0:
                    log.debug(f"Current remaining segment size: 0x{self._seg_size:X}")
                    if self._seg_size > self._block_len_max:
                        data_buf_len = self._block_len_max
                    else:
                        data_buf_len = self._seg_size
                    data_buf = self._current_to_send_block_raw_data[:data_buf_len]
                    self._current_to_send_block_raw_data = self._current_to_send_block_raw_data[data_buf_len:]
                    if self._block_sequence_counter == 256:
                        self._block_sequence_counter = 0
                    user_data_prefix = bytes.fromhex("36" + hex(self._block_sequence_counter)[2:].zfill(2))
                    self._current_uds_service = 0x36
                    message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=user_data_prefix + data_buf)
                    log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                    self._uds_state = UDSState.SENT
                    self._doip_send(message)
                    self._block_sequence_counter += 1
                    self._seg_size -= data_buf_len
                    return
                else:
                    self._uds_state = UDSState.IDLE
                    self._flash_state = FlashState.P_APP_REQUEST_TRANSFER_EXIT
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return
                
        if self._flash_state == FlashState.P_APP_REQUEST_TRANSFER_EXIT:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("37"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x37
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                # self._flash_state = FlashState.P_APP_CHECK_MEMORY_INTEGRITY
                self._current_app_block_index += 1
                self._flash_state = FlashState.P_APP_REQUEST_DOWNLOAD
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return    

        if self._flash_state == FlashState.P_APP_CHECK_MEMORY_INTEGRITY:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("31010202") + bytearray(b"fuck crc"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x31
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_CHECK_PROGRAMMING_DEPENDENCY
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return
                
        if self._flash_state == FlashState.P_CHECK_PROGRAMMING_DEPENDENCY:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("3101FF00"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x31
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.P_REQUEST_ECU_RESET
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return 

        # post programming
        if self._flash_state == FlashState.P_REQUEST_ECU_RESET:
            if self._uds_state == UDSState.IDLE:
                message = DiagnosticMessage(source_address=0x0001, target_address=self._target_address, user_data=bytes.fromhex("1101"))
                self._uds_state = UDSState.SENT
                self._doip_send(message)
                self._current_uds_service = 0x11
                log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
                return
            elif self._uds_state == UDSState.POSITIVE_RESPONSE:
                log.info(f"0x{self._current_uds_service:X} positive")
                self._uds_state = UDSState.IDLE
                self._flash_state = FlashState.F_POST_PROGRAMMING_EXTENDED_SESSION_SWITCH
                return
            elif self._uds_state == UDSState.NEGATIVE_RESPONSE:
                log.error(f"0x{self._current_uds_service:X} negative")
                self._current_client_running = False
                return
            elif self._uds_state == UDSState.PENDING:
                log.info(f"0x{self._current_uds_service:X} pending")
                return
            else:
                log.error("You should not get here!!!")
                self._current_client_running = False
                return 

        if self._flash_state == FlashState.F_POST_PROGRAMMING_EXTENDED_SESSION_SWITCH:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("1003"))
            self._doip_send(message)
            self._current_uds_service = 0x10
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.F_COMMUNICATION_CONTROL_ON
        
        if self._flash_state == FlashState.F_COMMUNICATION_CONTROL_ON:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("280001"))
            self._doip_send(message)
            self._current_uds_service = 0x28
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.F_CONTROL_DTC_ON

        if self._flash_state == FlashState.F_CONTROL_DTC_ON:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("8501"))
            self._doip_send(message)
            self._current_uds_service = 0x85
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.F_DEFAULT_SESSION_ON
        
        if self._flash_state == FlashState.F_DEFAULT_SESSION_ON:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0001, target_address=0xE400, user_data=bytes.fromhex("1001"))
            self._doip_send(message)
            self._current_uds_service = 0x10
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.FLASHED_OK
        
        if self._flash_state == FlashState.FLASHED_OK:
            log.info("DEMO flash OK!!!!!!!!!!!!!!!!!!")
            self._current_client_running = False

class RepeatTimer(Timer):
    def run(self):
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)

def tester_present(client):
    message = DiagnosticMessage(source_address=0x0001, target_address=0x0002, user_data=bytes.fromhex("3E80"))
    if client._doip_stack._is_edge_node_connected:
        client._doip_send(message)
        log.info("tester present")

def main():
    signal.signal(signal.SIGINT, signal_handler)

    client = DoIPClient(target_address=0x0002)
    stack = DoIPStack(client_ip_address="127.0.0.1", server_ip_address="127.0.0.1")
    client.daemon = True
    stack.daemon = True
    test_present_timer = RepeatTimer(interval=2, function=tester_present, args=(client, ))
    test_present_timer.daemon = True
    client._doip_stack = stack
    client.process_software_package()

    stack.register_master_client(0x0002, client=client)

    if stack.connect_edge_node(timeout=0.05) == 0:
        stack._is_edge_node_connected = True
        stack.start()
        client.start()
        # # TODO: Get the tester-present thread after routing activation, not brute-force sleep 2 seconds
        # time.sleep(2)
        # test_present_timer.start()

        while True:
            time.sleep(5)
            log.info("Main thread tick...")
            if client._current_client_running == False:
                # test_present_timer.cancel()
                break
    else:
        log.error("Connect failed.")

    log.info("About to exit......")

if __name__ == "__main__":
    main()
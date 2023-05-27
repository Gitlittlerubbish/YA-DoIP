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
import signal
from threading import Timer
from sys import platform

from stack import DoIPStack
import hexrec.records as hr
import binascii
from ctypes import *
import xml.dom.minidom


log = logging.getLogger("DoIP-CLIENT")
log.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(filename)s:%(funcName)s():%(lineno)d] [%(levelname)s] [%(thread)d] - %(message)s")
default_handler = logging.StreamHandler()
handler = RotatingFileHandler(filename=".\\log\\doip\\doip_client.log", maxBytes=5 * 1024 * 1024, backupCount=2)
log.addHandler(handler)
log.addHandler(default_handler)
handler.setFormatter(formatter)
default_handler.setFormatter(formatter)

log.info("DoIP CLIENT LOG init.")
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
    F_DEFAULT_SESSION_ON = 2
    # start
    """
        Finite State Machine of ISO 14229 stuff here
    """
    # over
    FLASHED_OK = 3
    FLASHED_FAIL = 4


class DoIPClient(threading.Thread):

    def __init__(self, doip_stack=None, id=0, target_address=0xABCD, doip_send=None):
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
        self._driver_blocks = list()
        self._current_driver_block_index = 0
        self._app_blocks = list()
        self._current_app_file_index = 0
        self._second_app_blocks = list()
        self._current_to_send_block_raw_data = 0x00
        self._seg_size = 0x00
        self._block_len_max = 0x00
        self._block_sequence_counter = 1
        self._data_buf_len = 0
        self._uds_event = threading.Event()
        
        super().__init__()

    def process_software_package(self):
        """
            You can do preparation here
        """
        pass

    def routing_activate_edge_node(self):
        self._doip_stack.routing_activate_edge_node()
        
    def routing_activate_edge_node_callback(self, response):
        """_summary_
            A master client needs to have this routing activation callback because the stack will call this function.
        Args:
            response (Routing Activation Response Message): 
        """
        if response.response_code == 0x10:
            self._flash_state = FlashState.EDGE_NODE_ROUTING_ACTIVATE
            log.info("Current node routing activated.")
        else:
            self._current_client_running = False
            log.info("Current node routing activation failed, code: 0x{}".format(response.response_code))
        log.debug("I am the routing activation callback of edge node.")
        self._uds_event.set()

    def doip_send_callback(self, message):
        log.info(f"0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data[:24].hex().upper()}")
        if self._uds_state == UDSState.IDLE:
            log.warning("UDS state IDLE, ignore......")
            return
        elif self._uds_state == UDSState.FUNCTIONAL_COLLECTING:
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
            elif True == True: # NOTE: positive UDS judge here
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
        
        self.routing_activate_edge_node()
        self._current_client_running = True
        while self._current_client_running:
            self._uds_event.wait(timeout=2.0)
            log.debug("DoIP callback event set.")
            self.process()
            self._uds_event.clear()
        
        log.info("Current client exit......")

    # This function for UDS flow control
    def process(self):
        log.info(f"Flash state: {self._flash_state.name}")
        if self._flash_state == FlashState.EDGE_NODE_ROUTING_ACTIVATE:
            self._flash_state == FlashState.F_DEFAULT_SESSION_ON

        if self._flash_state == FlashState.F_DEFAULT_SESSION_ON:
            self._uds_state = UDSState.FUNCTIONAL_COLLECTING
            message = DiagnosticMessage(source_address=0x0E80, target_address=0xE400, user_data=bytes.fromhex("1001"))
            self._doip_send(message)
            self._current_uds_service = 0x10
            log.info(f"{type(message)} 0x{message.source_address:X} -> 0x{message.target_address:X}: 0x{message.user_data.hex().upper()[:24]}")
            time.sleep(2.5)
            self._uds_state = UDSState.IDLE
            self._flash_state = FlashState.FLASHED_OK
        
        if self._flash_state == FlashState.FLASHED_OK:
            log.info("Current ECU flash OK!!!!!!!!!!!!!!!!!!")
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

    # initialization
    master_client = DoIPClient(target_address=0x1111)
    master_client.daemon = True
    client = DoIPClient(target_address=0x2222)
    client.daemon = True

    stack = DoIPStack(client_ip_address="127.0.0.1", server_ip_address="127.0.0.1")
    stack.daemon = True
    test_present_timer = RepeatTimer(interval=2.5, function=tester_present, args=(client, ))
    test_present_timer.daemon = True
    master_client._doip_stack = stack
    client._doip_stack = stack

    # register all the clients
    stack.register_master_client(0x1111, client=master_client)
    stack.register_client(0x2222, client=client)

    master_client.process_software_package()
    client.process_software_package()

    if stack.connect_edge_node(timeout=0.05) == 0:
        stack._is_edge_node_connected = True
        stack.start()
        master_client.start()
        # maybe you need some condition check here for the next two lines
        client.start()
        test_present_timer.start()

        while True:
            time.sleep(5)
            log.info("Main thread tick...")
            if master_client._current_client_running == False:
                test_present_timer.cancel()
                break
    else:
        log.error("EDGE NODE connect failed.")

    log.info("Going to exit.")

if __name__ == "__main__":
    main()
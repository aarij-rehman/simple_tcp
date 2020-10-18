import struct
import time
import concurrent.futures
from threading import Timer
import sys
from zlib import adler32
# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # Parameters for managing order
        self.current_receiving_SEQ = 0
        self.packing_seq = 0
        self.buffer = {}

        # Thread management
        self.closed = False
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.listen_thread = self.executor.submit(self.listener)

        # ACK management
        self.ACK = {}

        # FIN handshake 
        self.FIN = False # has the other party sent the fin message yet?

        # Pipelining
        self.sending_buffer = {}

        # Extra Credit 
        self.all_data = b""
        self.first_time = True



    def send(self, data_bytes: bytes) -> None:
        if self.first_time:
            Timer(0.01, self.__data_check, [len(data_bytes)]).start()
            self.first_time = False
        self.all_data += data_bytes
       
    def recv(self) -> bytes:    
        # If the desired packet is already in the buffer, return it. Othwerise, wait.
        while self.current_receiving_SEQ not in self.buffer:
            time.sleep(0.01)
        self.current_receiving_SEQ += 1
        return self.buffer.pop(self.current_receiving_SEQ-1)

    def close(self) -> None:
        self.__FIN_handshake()
        self.closed = True
        self.socket.stoprecv()
        while not self.listen_thread.done():
            time.sleep(0.01)
        self.executor.shutdown()

    def listener(self):
        while not self.closed: 
            try:
                data = self.socket.recvfrom()[0]
                self.__packet_handler(data)
            except Exception as e:
                print("listener died!")
                print(e)
        return 

#### HELPERS #####

    #### Sending helpers
    # Breaks data up into pieces no largers than 's'
    # and returns a list of broken up pieces 
    def __byte_breaker(self, b: bytes, s: int):
        return [b[i:i+s] for i in range(0, len(b), s)]
    
    # Sends data and starts a timer 
    def __recursive_send(self, seq):
        to_send = self.sending_buffer[seq]
        self.socket.sendto(to_send, (self.dst_ip, self.dst_port))
        Timer(1, self.__selective_repeat, [seq]).start()
        return

    # Checks if ACK is received. Calls __recursive_send if not.
    def __selective_repeat(self, seq):
        if seq not in self.ACK:
            return self.__recursive_send(seq)      


    #### Nagles Algorithm Helpers (EC) 
    # Checks if there has been more data added to sending queue. If not, sends, otherwise
    # it starts a timer to check again in 1 ms.
    def __data_check(self, num):
        if len(self.all_data) > num:
            return Timer(0.01, self.__data_check, [len(self.all_data)]).start()
        return self.__send_data()

    # Takes the whole sending queue and sends it out with __recursive send for 
    # guaranteed delivery.
    def __send_data(self):
        byte_ls = self.__byte_breaker(self.all_data, 1456)
        for data in byte_ls:
            to_send = self.__packer(self.packing_seq, data, ack=False)
            self.sending_buffer[self.packing_seq] = to_send
            self.__recursive_send(self.packing_seq)
            self.packing_seq += 1
        self.first_time = True
        self.all_data = b''


    #### Helpers for packing and unpacking data with structs
    # Packs a sequence number, data, ACK flag, and hash into a struct
    def __packer(self, seq, data, ack=False) -> struct:
        f = f'h {len(data)}s b'
        insecure_struct = struct.pack(f, seq, data, ack)
        secure_struct = self.__hash_pack(insecure_struct)
        return secure_struct

    # Unpacks a struct w/ a hash, sequence number, data, and ACK 
    def __unpacker(self, packed) -> tuple:
        f = f'i h {len(packed)-7}s b'
        return struct.unpack(f, packed)

    #### Flow Control Helpers
    # General function that deals with received packets. Sends things 
    # where they need to go depending on the type/state of the packet
    def __packet_handler(self, _data):
        if not _data:
            return
        seq, seg, ack = self.__unpacker(_data)[1:]
        if not self.__hash_check(_data):
            return 
        if ack:
            self.ACK[seq] = True   
        elif seq == -1:
            self.FIN = True
            self.__send_ACK(seq)
        else:
            self.buffer[seq] = seg
            self.__send_ACK(seq)

    # Sends an ACK for a given seq number
    def __send_ACK(self, seq):
        f = 'h s b'
        s = struct.pack(f, seq, b'a', True)
        s = self.__hash_pack(s)
        self.socket.sendto(s, (self.dst_ip, self.dst_port))

 
    #### Helpers for the FIN handshake
    # Recursively sends a FIN message to indicate that we're done sending
    def __send_fin(self) -> None:
        FIN = struct.pack('h 4s b', -1, b'done', False)
        FIN = self.__hash_pack(FIN)
        self.socket.sendto(FIN, (self.dst_ip, self.dst_port))
        self.__wait_fin_ACK()

    # Waits until an ACK for the FIN is received. If it's not recieved 
    # soon enough, it resends the FIN.
    def __wait_fin_ACK(self):
        count = 0
        while -1 not in self.ACK:
            time.sleep(0.01)
            count += 1
            if count > 25:
                self.__send_fin()

    # 1) Sends a message to indicate we're done sending data
    # 2) Waits until we receive message 
    # 3) After receiving the FIN, we wait two seconds to make sure our FIN ACK
    #    doesn't get lost
    def __FIN_handshake(self):
        self.__send_fin()
        while not self.FIN:
            time.sleep(0.01)
        time.sleep(3)
        

    #### Helpers for creating and verifying hashes 
    # Given a packed struct, adds a hash to it
    def __hash_pack(self, _struct):
        f = f'i {len(_struct)}s'
        code = adler32(_struct) % 2147483647 # keeps the result a 32 bit integer
        return struct.pack(f, code, _struct)

    # Given a packed struct, determines if the hash is valid
    def __hash_check(self, _data):
        expected = self.__unpacker(_data)[0]
        actual = adler32(_data[4:]) % 2147483647 
        return expected == actual
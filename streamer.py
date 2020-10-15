import struct
import time
import concurrent.futures
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
        self.current_sending_SEQ = 0
        self.buffer = {}

        # Thread management
        self.closed = False
        self.executor =  concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.thread = self.executor.submit(self.listener)

        # ACK management
        self.ACK = {}
        self.FIN = False

    def send(self, data_bytes: bytes) -> None:
        byte_ls = self.__byte_breaker(data_bytes, 1456)
        for data in byte_ls:
            to_send = self.__packer(self.current_sending_SEQ, data, ack=False)
            self.socket.sendto(to_send, (self.dst_ip, self.dst_port))
            # Wait for acknowledgement
            self.__wait_ACK(data)
            self.current_sending_SEQ += 1

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""      
        # If the desired packet is already in the buffer, return it. Othwerise, wait.
        while self.current_receiving_SEQ not in self.buffer:
            time.sleep(0.01)
        self.current_receiving_SEQ += 1
        return self.buffer.pop(self.current_receiving_SEQ-1)


    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        self.__send_fin()
        while not self.FIN:
            time.sleep(0.01)
        self.closed = True
        self.socket.stoprecv()
        while not self.thread.done():
            time.sleep(0.01)
        self.executor.shutdown()

    def listener(self):
        while not self.closed: 
            try:
                data, addr = self.socket.recvfrom()
                self.__packet_handler(data)
            except Exception as e:
                print("listener died!")
                print(e)
        print ('the thread has returned ')
        return 

#### HELPERS #####

    #### Self.send() helpers
    # Breaks data up into pieces no largers than 's'
    # and returns a list of broken up pieces 
    def __byte_breaker(self, b: bytes, s: int):
        return [b[i:i+s] for i in range(0, len(b), s)]


    #### Helpers for packing and unpacking data with structs
    # Packs a sequence number, data, ACK flag, and hash into a struct
    def __packer(self, seq, data, ack=False) -> struct:
        f = f'i {len(data)}s b'
        insecure_struct = struct.pack(f, seq, data, ack)
        secure_struct = self.__hash_pack(insecure_struct)
        return secure_struct

    # Unpacks a struct w/ a hash, sequence number, data, and ACK. Doesn't return the hash 
    def __unpacker(self, packed) -> tuple:
        f = f'i i {len(packed)-9}s b'
        return struct.unpack(f, packed)

    def __packet_handler(self, _data):
        if not _data:
            return
        check, seq, seg, ack = self.__unpacker(_data)
        if not self.__hash_check(_data):
            return 
        if seq == -1:
            self.FIN = True
        elif ack:
            self.ACK[seq] = True
        else:
            self.buffer[seq] = seg
            self.__send_ACK(seq)

    def __send_ACK(self, seq):
        f = 'i s b'
        s = struct.pack(f, seq, b'a', True)
        s = self.__hash_pack(s)
        self.socket.sendto(s, (self.dst_ip, self.dst_port))

    def __wait_ACK(self, data):
        count = 0
        while self.current_sending_SEQ not in self.ACK:
            time.sleep(0.01)
            count += 1
            if count > 25:
                self.send(data)
                self.current_sending_SEQ -= 1
                return

    def __send_fin(self) -> None:
        FIN = struct.pack('i 4s b', -1, b'done', False)
        self.socket.sendto(FIN, (self.dst_ip, self.dst_port))

    #### Helpers for creating and verifying hashes 
    # Given a packed struct, adds a hash to it
    def __hash_pack(self, _struct):
        f = f'i {len(_struct)}s'
        return struct.pack(f, adler32(_struct), _struct)

    # Given a packed struct, determines if the hash is valid
    def __hash_check(self, _data):
        expected = self.__unpacker(_data)[0]
        actual = adler32(_data[4:])
        if expected != actual:
            print('corrupt!')
        return expected == actual

# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
import time
import concurrent.futures
import sys


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

    def send(self, data_bytes: bytes) -> None:
        byte_ls = self.__byte_breaker(data_bytes, 1468)
        for data in byte_ls:
            to_send = self.__packer(self.current_sending_SEQ, data)
            self.socket.sendto(to_send, (self.dst_ip, self.dst_port))
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
        # your code goes here, especially after you add ACKs and retransmissions.
        self.closed = True
        self.socket.stoprecv()
        while not self.thread.done():
            time.sleep(0.01)
        print(self.thread.cancel())
        self.executor.shutdown()

    def listener(self):
        while not self.closed: 
            try:
                data, addr = self.socket.recvfrom()
                if data:
                    seq, seg = self.__unpacker(data)
                self.buffer[seq] = seg
            except Exception as e:
                print("listener died!")
                print(e)
        print ('the thread has returned ')
        return 

    def __byte_breaker(self, b: bytes, s: int):
        return [b[i:i+s] for i in range(0, len(b), s)]

    def __packer(self, seq, data) -> struct:
        f = f'i {len(data)}s'
        return struct.pack(f, seq, data)
    
    def __unpacker(self, packed) -> tuple:
        f = f'i {len(packed)-4}s'
        return struct.unpack(f, packed)

    def __send_fin(self) -> None:
        FIN = struct.pack('i 4s', -1, b'done')
        self.socket.sendto(FIN, (self.dst_ip, self.dst_port))

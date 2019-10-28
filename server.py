import time
import struct
import socket
from hashlib import sha1
from base64 import b64encode
import sys
from select import select
import re
import logging
from threading import Thread
import signal
def make_handshake_response(key):
        return \
          'HTTP/1.1 101 Switching Protocols\r\n'\
          'Upgrade: websocket\r\n'              \
          'Connection: Upgrade\r\n'             \
          'Sec-WebSocket-Accept: %s\r\n'        \
          '\r\n' % calculate_response_key(key)

def calculate_response_key(key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(hash.digest()).strip()
        return response_key.decode('ASCII')

MAGICGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TEXT = 0x01
BINARY = 0x02

class WebSocket(object):
    def __init__(self, client, server):
        self.client = client
        self.server = server
        self.handshaken = False
        self.header = ""
        self.data = ""

    def feed(self, data):
    
        if not self.handshaken:
            logging.debug("No handshake yet")
            self.header += data.decode()
            if self.header.find('\r\n\r\n') != -1:
                parts = self.header.split('\r\n\r\n', 1)
                self.header = parts[0]
                if self.dohandshake(self.header, parts[1]):
                    logging.info("Handshake successful")
                    self.handshaken = True
        else:
            logging.debug("Handshake is complete")
            
            recv = self.decodeCharArray(data)
            self.sendMessage(''.join(recv).strip());

    def sendMessage(self, s):
        """
        Encode and send a WebSocket message
        """       
        message = ""
        b1 = 0x80
        if type(s) == str:
            b1 |= TEXT
            payload = s
        message += chr(b1)
        b2 = 0
        
        length = len(payload)
        if length < 126:
            b2 |= length
            message += chr(b2)
        
        elif length < (2 ** 16) - 1:
            b2 |= 126
            message += chr(b2)
            l = struct.pack(">H", length)
            message += l
        
        else:
            l = struct.pack(">Q", length)
            b2 |= 127
            message += chr(b2)
            message += l

        message += payload

        self.client.send(message.encode())


    def decodeCharArray(self, stringStreamIn):
        byteArray = [character for character in stringStreamIn]
        datalength = byteArray[1] & 127
        indexFirstMask = 2
        if datalength == 126:
            indexFirstMask = 4
        elif datalength == 127:
            indexFirstMask = 10
        masks = [m for m in byteArray[indexFirstMask : indexFirstMask+4]]
        indexFirstDataByte = indexFirstMask + 4
        
        decodedChars = []
        i = indexFirstDataByte
        j = 0
        
        while i < len(byteArray):
        
            decodedChars.append( chr(byteArray[i] ^ masks[j % 4]) )
            i += 1
            j += 1

        return decodedChars


    def dohandshake(self, header, key=None):
    
        logging.debug("Begin handshake: %s" % header)
            
        for line in header.split('\r\n')[1:]:
            name, value = line.split(': ', 1)
            
            if name.lower() == "sec-websocket-key":
            
                
                handshake =  make_handshake_response(value)

        logging.debug("Sending handshake %s" % handshake)
        self.client.send(handshake.encode())
        return True

    def onmessage(self, data):
        print("helloooo")
        self.send(data)

    def send(self, data):
        logging.info("Sent message: %s" % data)
        self.client.send("\x00%s\xff" % data)

    def close(self):
        self.client.close()


class WebSocketServer(object):

    def __init__(self, bind, port, cls):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((bind, port))
        self.bind = bind
        self.port = port
        self.cls = cls
        self.connections = {}
        self.listeners = [self.socket]

    def listen(self, backlog=5):

        self.socket.listen(backlog)
        logging.info("Listening on %s" % self.port)

        # Keep serving requests
        self.running = True
        while self.running:
        
            # Find clients that need servicing
            rList, wList, xList = select(self.listeners, [], self.listeners, 1)
            for ready in rList:
                if ready == self.socket:
                    logging.debug("New client connection")
                    client, address = self.socket.accept()
                    fileno = client.fileno()
                    self.listeners.append(fileno)
                    self.connections[fileno] = self.cls(client, self)
                else:
                    logging.debug("Client ready for reading %s" % ready)
                    client = self.connections[ready].client
                    data = client.recv(4096)
                    fileno = client.fileno()
                    if data:
                        self.connections[fileno].feed(data)
                    else:
                        logging.debug("Closing client %s" % ready)
                        self.connections[fileno].close()
                        del self.connections[fileno]
                        self.listeners.remove(ready)
            
            # Step though and delete broken connections
            for failed in xList:
                if failed == self.socket:
                    logging.error("Socket broke")
                    for fileno, conn in self.connections:
                        conn.close()
                    self.running = False

# Entry point
if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    server = WebSocketServer("", 8001, WebSocket)
    server_thread = Thread(target=server.listen, args=[5])
    server_thread.start()

    # Add SIGINT handler for killing the threads
    def signal_handler(signal, frame):
        logging.info("Caught Ctrl+C, shutting down...")
        server.running = False
        sys.exit()
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        time.sleep(100)
import time
import struct
import subprocess 
import socket
from hashlib import sha1
from base64 import b64encode
import sys
from select import select
import re
import logging
from threading import Thread
import signal
FIN    = 0x80
OPCODE = 0x0f
OPCODE_TEXT         = 0x1
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

user_data = {"Rachana":"rachana"}
import os
def validate_username(username):
    if username in user_data.keys():
        user = username
        return 1
    else :
        return 0

def validate_password(user, password):
    if user_data[user] == password:
        return 1
    else:
        return 0

def execute_command(command):
    """execute commands and handle piping"""
    try:
        return subprocess.check_output(command ,shell = True)
    except Exception:
        return("command not found: {}".format(command))
    

def cd_func(path):
    """convert to absolute path and change directory"""
    try:
        os.chdir(os.path.abspath(path))
        return("")
    except Exception:
        return("cd: no such file or directory: {}".format(path))

def doThing(inp):
        if inp[:3] == "cd ":
            return cd_func(inp[3:])

        else:
            return execute_command(inp)


def encode_to_UTF8(data):
        try:
            return data.encode('UTF-8')
        except UnicodeEncodeError as e:
            logging.error("Could not encode data to UTF-8 -- %s" % e)
            return False
        except Exception as e:
            raise(e)
            return False

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
        self.state = 0
        self.user = ""


    def feed(self, data):
    
        if not self.handshaken:
            logging.debug("No handshake yet")
            self.header += data.decode()
            if self.header.find('\r\n\r\n') != -1:
                parts = self.header.split('\r\n\r\n', 1)
                self.header = parts[0]
                if self.dohandshake(self.header, parts[1]):
                    logging.info("Handshake successful")
                    self.sendMessage("Enter Username : ")
                    self.state = 1 
                    self.handshaken = True
        else:
            logging.debug("Handshake is complete")
            
            recv = self.decodeCharArray(data)
            cmd = ''.join(recv).strip()
            if self.state == 1:
                validation = validate_username(cmd)
                if validation == 1:
                    self.state = 2
                    self.user = cmd
                    self.sendMessage("Enter Password : ")
                else:
                    self.state = 1
                    self.sendMessage("Invalid User! <br> Enter Username : ")
            elif self.state == 2 :
                password_validation = validate_password(self.user,cmd)
                if password_validation == 1:
                    self.sendMessage(self.user + " logged in.")
                    self.state = 0
                else:
                    self.sendMessage("Wrong Password!")
                    self.sendMessage("Enter Password : ")
                    self.state = 2
            else:
                output = doThing(cmd)
                self.sendMessage(output);
                logging.debug("Input: "+''.join(recv).strip())
                if(type(output)==str):
                    logging.debug("Output: "+output)
                else:
                    logging.debug("Output: "+ output.decode())

    def sendMessage(self, message):
        opcode = OPCODE_TEXT
        header  = bytearray()
        if(type(message) == bytes):
            message = message.decode()
        message = message.replace("\n","<br>")
        payload = encode_to_UTF8(message)
        payload_length = len(payload)

        # Normal payload
        if payload_length <= 125:
            header.append(FIN | opcode)
            header.append(payload_length)

        # Extended payload
        elif payload_length >= 126 and payload_length <= 65535:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_length))

        # Huge extended payload
        elif payload_length < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.extend(struct.pack(">Q", payload_length))

        else:
            raise Exception("Message is too big. Consider breaking it into chunks.")
            return

        self.client.send(header + payload)



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
    server = WebSocketServer("", 8002, WebSocket)
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


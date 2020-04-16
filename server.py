#The handshake is the "Web" in WebSockets.
#  It's the bridge from HTTP to WebSockets.
#  In the handshake, details of the connection are negotiated, 
#  and either party can back out before completion if the terms are unfavorable.

# WebSocket is a computer communications protocol, providing full-duplex communication channels over a single TCP connection
import time
import struct
import subprocess 
import socket
from hashlib import sha1
from base64 import b64encode
import base64
import sys
from select import select
import re
import logging
from threading import Thread
import signal
from Crypto.Cipher import AES
import os
from Crypto import Random
from hashlib import md5
import hashlib, uuid

FIN    = 0x80
OPCODE = 0x0f
OPCODE_TEXT = 0x1
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f
BLOCK_SIZE = 16
TEXT = 0x01
BINARY = 0x02

# Maintaining user data in a dictionary after reading from user_data.txt
user_data = {}

f = open("user_data.txt","r");
for line in f.readlines():
    data = line.split()
    user_data[data[0]] = data[1]

logging.info("USER DATA : " + str(user_data))

# Unpadding data before decryption
def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

# Desalting the key
def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]

# Decrypting the password with symmetric key = "Secret Passphrase"
def decrypt(encrypted, passphrase = "Secret Passphrase".encode()):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))

# Validating username
def validate_username(username):    
    if username in user_data.keys():
        user = username
        return 1
    else :
        return 0

# Validating password
def validate_password(user, password):
    password = decrypt(password).decode("utf-8") 
    logging.debug(password)
    hashed_password = hashlib.sha512((password).encode()).hexdigest()
    logging.debug(hashed_password)
    if user_data[user] == hashed_password:
        return 1
    else:
        return 0

# Executing Command
def execute_command(command):
    try:
        return subprocess.check_output(command ,shell = True)
    except Exception:
        return("command not found: {}".format(command))
    
# Handles cd based functions
def cd_func(path):
    # convert to absolute path and change directory
    try:
        os.chdir(os.path.abspath(path))
        return("")
    except Exception:
        return("cd: no such file or directory: {}".format(path))

# Checks if command is cd based or if it is a normal command
def process_command(inp):
        if inp[:3] == "cd ":
            return cd_func(inp[3:])

        else:
            return execute_command(inp)

# Handling encoding errors
def encode_to_UTF8(data):
        try:
            return data.encode('UTF-8')
        except UnicodeEncodeError as e:
            logging.error("Could not encode data to UTF-8 -- %s" % e)
            return False
        except Exception as e:
            raise(e)
            return False

# Handshake response key
def make_handshake_response(key):
        return \
          'HTTP/1.1 101 Switching Protocols\r\n'\
          'Upgrade: websocket\r\n'              \
          'Connection: Upgrade\r\n'             \
          'Sec-WebSocket-Accept: %s\r\n'        \
          '\r\n' % calculate_response_key(key)

# Calculating handshake response key
# When the server receives the handshake request, 
# it should send back a special response that indicates that the protocol will be 
# changing from HTTP to WebSocket.
def calculate_response_key(key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(hash.digest()).strip()
        return response_key.decode('ASCII')


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
          
            logging.debug("Handshake is already complete")
            
            recv = self.decodeCharArray(data)
            cmd = ''.join(recv).strip()
          
            # Username has to be entered
            if self.state == 1:
          
                validation = validate_username(cmd)
                if validation == 1:
                    self.state = 2
                    self.user = cmd
                    self.sendMessage("Enter Password : ")
                else:
                    self.state = 1
                    self.sendMessage("Invalid User! <br> Enter Username : ")
            
            # Password has to be entered
            elif self.state == 2 :
         
                password_validation = validate_password(self.user,cmd)
                if password_validation == 1:
                    self.sendMessage(self.user + " logged in.")
                    self.state = 0
                else:
                    self.sendMessage("Wrong Password!")
                    self.sendMessage("Enter Password : ")
                    self.state = 2
            
            # Command has to be entered
            else:
                output = process_command(cmd)
                self.sendMessage(output);
                logging.debug("Input: "+''.join(recv).strip())
                if(type(output)==str):
                    logging.debug("Output: "+output)
                else:
                    logging.debug("Output: "+ output.decode())

    # Sends message
    def sendMessage(self, message):
        # The FIN bit tells whether this is the last message in a series.
        opcode = OPCODE_TEXT 
        # The opcode field defines how to interpret the payload data:
        # 0x0 for continuation, 0x1 for text (which is always encoded in UTF-8), 0x2 for binary,
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

        self.client.send(header + payload)

# To read the payload data, you must know when to stop reading. That's why the payload length is important to know. Unfortunately, this is somewhat complicated. To read it, follow these steps:
# Read bits 9-15 (inclusive) and interpret that as an unsigned integer. If it's 125 or less, then that's the length; you're done. If it's 126, go to step 2. If it's 127, go to step 3.
# Read the next 16 bits and interpret those as an unsigned integer. You're done.
# Read the next 64 bits and interpret those as an unsigned integer (The most significant bit MUST be 0). You're done.
    def decodeCharArray(self, stringStreamIn):
        byteArray = [character for character in stringStreamIn]
        datalength = byteArray[1] & 127
        indexFirstMask = 2
        if datalength == 126:
            indexFirstMask = 4
        elif datalength == 127:
            indexFirstMask = 10
        masks = [m for m in byteArray[indexFirstMask : indexFirstMask+4]] # The MASK bit simply tells whether the message is encoded.
        indexFirstDataByte = indexFirstMask + 4
        
        decodedChars = []
        i = indexFirstDataByte
        j = 0
        
        while i < len(byteArray):
        
            decodedChars.append( chr(byteArray[i] ^ masks[j % 4]) )
            i += 1
            j += 1

        return decodedChars

    # Process exists so that it's obvious to the client whether or not the server supports WebSockets. 
    # This is important because security issues might arise if the server accepts a WebSockets connection 
    # but interprets the data as a HTTP request.

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


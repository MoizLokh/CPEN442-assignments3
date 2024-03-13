import base64
from hashlib import pbkdf2_hmac
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import json

from DHKeyExchange import DH

class Protocol:
    CHALLENGE_LENGTH=16
    TAG_LENGTH=16
    KEY_LENGTH=16
    SALT_LENGTH = 16
    Verbose = True

    INIT = "init"
    WAIT_FOR_CLIENT = "waitForClient"
    WAIT_FOR_SERVER = "waitForServer"
    ESTABLISHED = "established"

    AUTH_MSG_SRVR = "key_exchange_srvr"
    AUTH_MSG_CLNT = "key_exchange_clnt"
    INIT_MSG = "key_exchange_init"

    # Initializer (Called from app.py)
    def __init__(self, mutual_key):
        self._key = None
        self.mutual_key = mutual_key
        self.challenge = ""
        self.state = "init"
        self.dh = None

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self):
        # (Init) -> Waiting for server message
        
        self.dh = DH()
        self.challenge = self._createNewChallenge()
        self._setStateTo(self.WAIT_FOR_SERVER)
        return self._createSendMessage(self.INIT_MSG)


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        # receiving message is always a protocol message if state is not established
        try:
            jsonMsg = json.loads(message.decode())
            isProto = any([jsonMsg["type"] == x for x in [self.INIT_MSG, self.AUTH_MSG_CLNT, self.AUTH_MSG_SRVR]])
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)
            isProto = False

        return isProto


    # Processing protocol message
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # <ID>,<Rc>          MSG_TYPE:INIT       (Init) -> Waiting for client message
        # <Es>,<Hs>,<Rs>     MSG_TYPE:AUTH       (Client: Waiting for server message) -> Established
        # <Ec>,<Hc>,<Rc>     MSG_TYPE:AUTH       (Server: Waiting for client message) -> Established

        sendMsg = ""

        try:
            jsonMsg = json.loads(message.decode())
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)
            return sendMsg

        if self.state == self.INIT:
            if jsonMsg["type"] == "key_exchange_init":
                # Send AuthMsg Srv
                self.dh = DH()
                self.challenge = self._createNewChallenge()
                sendMsg = self._createSendMessage(self.AUTH_MSG_SRVR, jsonMsg)
                self._setStateTo(self.WAIT_FOR_CLIENT)
            else:
                print("Error") # error state failed logic
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_CLIENT:
            decriptJson, verified = self.decrypt(jsonMsg["encrypted"], self.mutual_key)

            if jsonMsg["type"] == self.AUTH_MSG_CLNT and verified:
                # Don't send msg
                self.SetSessionKey(self.dh.generate_shared_session_key(decriptJson["dh"]))
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_SERVER:
            decriptJson, verified = self.decrypt(jsonMsg["encrypted"], self.mutual_key) 

            if jsonMsg["type"] == self.AUTH_MSG_SRVR and verified:
                # Send AuthMsg client
                self.SetSessionKey(self.dh.generate_shared_session_key(decriptJson["dh"]))
                sendMsg = self._createSendMessage(self.AUTH_MSG_CLNT, jsonMsg)
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                # TODO: Send an error message here?
                self._setStateTo(self.INIT)

        return sendMsg


    # Established key for each session will have constant length size of 16. Relies on the secure
    # hash function https://pycryptodome.readthedocs.io/en/latest/src/hash/shake128.html to ensure
    # the length of the key is always 16
    def SetSessionKey(self, key):
        print(f"Setting session key based on Diffie Hellman")
        hashFn = SHAKE128.new()
        hashFn.update(str(key).encode())
        self._key = hashFn.read(Protocol.KEY_LENGTH).hex()

    # Encryption function used for messages encrypted with the session key
    def EncryptAndProtectMessage(self, plain_text):

        # See example from: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        print(f"Encryption says: {plain_text}")

        # EAX mode requires nonce and also produces tag for integrity checking
        nonce = get_random_bytes(Protocol.KEY_LENGTH)
        AES_cipher = AES.new(key=self._key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)
        ciphertext, mac_tag = AES_cipher.encrypt_and_digest(plain_text.encode())

        # Combine all messages into one
        cipher_text_combined = nonce+ciphertext+mac_tag
        print(f"Encryption says: {cipher_text_combined}")
        return cipher_text_combined

    # Decryption function used for messages encrypted with the session key
    def DecryptAndVerifyMessage(self, cipher_text):
        # See example from: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

        print(f"Decryption says: {cipher_text}")

        # Extract nonce, message, and tag in that order
        nonce = cipher_text[:Protocol.KEY_LENGTH]
        encrypted_message = cipher_text[Protocol.KEY_LENGTH:-Protocol.TAG_LENGTH]
        mac_tag = cipher_text[-Protocol.TAG_LENGTH:]

        # Do verification and decryption
        AES_cipher = AES.new(key=self._key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)

        try:
            message = AES_cipher.decrypt_and_verify(encrypted_message, mac_tag)
            print("Message integrity verified, tag does match!")
            return message
        except ValueError:
            print("Message integrity has been compromised, tag does not match!")

    def _setStateTo(self, next_state):
        if self.Verbose:
            print(self.state + " --> " + next_state)
        self.state = next_state

    def _createSendMessage(self, MSG_TYPE, receivedChallenge = ""):
        response = None

        if MSG_TYPE == self.INIT_MSG:
            response = {
                "type": MSG_TYPE,
                "challenge": self.challenge
            }
            
        if MSG_TYPE == self.AUTH_MSG_SRVR:
            response = {
                "type": MSG_TYPE,
                "encrypted": self.encrypt("SVR", self.dh.own_public_key, receivedChallenge, self.mutual_key),
                "challenge": self.challenge
            }
            
        if MSG_TYPE == self.AUTH_MSG_CLNT:
            response = {
                "type": MSG_TYPE,
                "encrypted": self.encrypt("CLNT", self.dh.own_public_key, receivedChallenge, self.mutual_key)
            }

        return json.dumps(response)

    # Return a random challenge for the current node instance
    def _createNewChallenge(self):
        return base64.b64encode(get_random_bytes(Protocol.CHALLENGE_LENGTH)).decode('ascii')
    
    # Encrypts message for key exchange part of mutual authentication - this should use MASTER SECRET KEY
    def encrypt(self, sender, dhKey, challenge, mutual_key):
        print("encrypt" + mutual_key.get())
        data = json.dumps({"sender": sender, "dh": dhKey, "challenge": challenge})
        
        # Generate a salt for PBKDF2
        salt = os.urandom(self.SALT_LENGTH)
        
        # Derive a key using PBKDF2 HMAC
        # Note: mutual_key needs to be bytes. If it's a string, convert it using mutual_key.encode()
        key = pbkdf2_hmac(
            hash_name='sha256',  # Specifies the hash function to use
            password=mutual_key.get().encode(),
            salt=salt,
            iterations=100000,
            dklen=32  # Desired key length in bytes
        )
        
        nonce = get_random_bytes(Protocol.KEY_LENGTH)
        AES_cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)
        ciphertext, mac_tag = AES_cipher.encrypt_and_digest(data.encode())

        # You might want to return the salt too, depending on how you manage it
        ret = base64.b64encode(salt + nonce + ciphertext + mac_tag).decode('utf-8')
        print(ret)
        return ret


    # Decrypts message for key exchange part of mutual authentication - this should use MASTER SECRET KEY
    def decrypt(self, encrypted_message_srt, mutual_key):
        print("d" + mutual_key.get())
        print(encrypted_message_srt)
        #Convert Base64 encoded string back to bytes
        encrypted_message = base64.b64decode(encrypted_message_srt)
                      
        # Extract the salt, nonce, and encrypted message + tag from the combined data
        salt = encrypted_message[:self.SALT_LENGTH]
        nonce = encrypted_message[self.SALT_LENGTH:self.SALT_LENGTH + self.KEY_LENGTH]
        encrypted_data = encrypted_message[self.SALT_LENGTH + self.KEY_LENGTH:-self.TAG_LENGTH]
        mac_tag = encrypted_message[-self.TAG_LENGTH:]

        # Derive the key using PBKDF2 HMAC, identical to the encryption process
        key = pbkdf2_hmac(
            hash_name='sha256',
            password=mutual_key.get().encode(),  # Assuming mutual_key is a StringVar and needs to be bytes
            salt=salt,  # The same salt used during encryption
            iterations=100000,
            dklen=32
        )
        # Do verification and decryption
        AES_cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)

        try:
            message = AES_cipher.decrypt_and_verify(encrypted_data, mac_tag)
            print("Message integrity verified, tag does match!")

            json_data = json.loads(message.decode())
            if json_data["challenge"]['challenge'] == self.challenge:
                return (json_data, True)
            else:
                print("Failed to verify received challenge")
                return (None, False)
        except ValueError:
            print("Message integrity has been compromised, tag does not match!")
            return (None, False)

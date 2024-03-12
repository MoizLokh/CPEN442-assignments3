from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes

import json

class Protocol:
    CHALLENGE_LENGTH=16
    TAG_LENGTH=16
    KEY_LENGTH=16
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
        self.df = None

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self):
        # (Init) -> Waiting for server message

        # TODO: Create a DH object
        # self.dh = DH()
        self.challenge = self._createNewChallenge()
        self._setStateTo(self.WAIT_FOR_SERVER)
        return self._createSendMessage(self.INIT_MSG)


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        # receiving message is always a protocol message if state is not established
        try:
            jsonMsg = json.loads(message)
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
            jsonMsg = json.loads(message)
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)
            return sendMsg

        if self.state == self.INIT:
            if jsonMsg["type"] == "key_exchange_init":
                # Send AuthMsg Srv
                # TODO: Create a DH object
                #self.dh = DH()
                self.challenge = self._createNewChallenge()
                sendMsg = self._createSendMessage(self.AUTH_MSG_SRVR, jsonMsg)
                self._setStateTo(self.WAIT_FOR_CLIENT)
            else:
                print("Error") # error state failed logic
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_CLIENT:
            decriptJson, verified = self.decrypt(jsonMsg["encrypted"])

            if jsonMsg["type"] == self.AUTH_MSG_CLNT and verified:
                # Don't send msg
                self.dh.compSK(decriptJson["dh"])
                self.SetSessionKey(self.dh.SK)
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_SERVER:
            decriptJson, verified = self.decrypt(jsonMsg["encrypted"])

            if jsonMsg["type"] == self.AUTH_MSG_SRVR and verified:
                # Send AuthMsg client
                self.dh.compSK(decriptJson["dh"])
                self.SetSessionKey(self.dh.SK)
                sendMsg = self._createSendMessage(self.AUTH_MSG_CLNT, jsonMsg["challenge"])
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
        hashFn.update(key.encode())
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
                "encrypted": self.encrypt(self.df.A, receivedChallenge),
                "challenge": self.challenge
            }
            
        if MSG_TYPE == self.AUTH_MSG_CLNT:
            response = {
                "type": MSG_TYPE,
                "encrypted": self.encrypt(self.df.A, receivedChallenge)
            }

        return response

    # TODO: Return a random challenge for the current node instance
    def _createNewChallenge(self):
        return get_random_bytes(Protocol.CHALLENGE_LENGTH)
    
    # Encrypts message for key exchange part of mutual authentication - this should use MASTER SECRET KEY
    def encrypt(self, sender, dhKey, challenge, key):
        data = json.dumps({"sender": sender, "dh": dhKey, "challenge": challenge})

        nonce = get_random_bytes(Protocol.KEY_LENGTH)
        AES_cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)
        ciphertext, mac_tag = AES_cipher.encrypt_and_digest(data.encode())

        return nonce+ciphertext+mac_tag
    
    # Decrypts message for key exchange part of mutual authentication - this should use MASTER SECRET KEY
    def decrypt(self, encrypted_message, key):
        
        # Extract nonce, message, and tag in that order
        nonce = encrypted_message[:Protocol.KEY_LENGTH]
        encrypted_message = encrypted_message[Protocol.KEY_LENGTH:-Protocol.TAG_LENGTH]
        mac_tag = encrypted_message[-Protocol.TAG_LENGTH:]

        # Do verification and decryption
        AES_cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)

        try:
            message = AES_cipher.decrypt_and_verify(encrypted_message, mac_tag)
            print("Message integrity verified, tag does match!")

            json_data = json.loads(message.decode())
            if json_data["challenge"] == self.challenge:
                return (json_data, True)
            else:
                return (None, False)
        except ValueError:
            print("Message integrity has been compromised, tag does not match!")
            return (None, False)

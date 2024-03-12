import os


class Message:
    def __init__(self, message):
        self.msg = message
        self.challenge = ""
        self._parseMsg()
    pass

    def _parseMsg(self):
        pass
            

class InitMessage(Message):
    def __init__(self, message):
        self.message = message
        self.id = ""
        self.challenge_received = 0
        Message.__init__(self, message)

    def _parseMsg(self):
        self.id = self.message['type']
        self.challenge_received = self.message['data']['challenge']
        

class AuthMessage(Message):
    SERVER = 0
    CLIENT = 1

    def __init__(self, message):
        self.id = ""
        self.encryptMsg = ""
        self.DH = 0
        self.challenge_received = 0

        Message.__init__(self, message)

    def verifyMsg(self):
        # Decript and compare hash
        return True

    def _parseMsg(self):
        # <E("SRVR/CLNT",g^a mod p,Ra>,H(..),Rb
        self.id = self.message['type']
        self.encryptMsg = self.message['data']['encryptMsg']
        self.DH = self.message['data']['DH']
        if self.message['type'] == 'key_exchange_clnt':
            self.challenge_received = self.message['data']['challenge']


class Protocol:
    Verbose = True

    INIT = "init"
    WAIT_FOR_CLIENT = "waitForClient"
    WAIT_FOR_SERVER = "waitForServer"
    ESTABLISHED = "established"

    AUTH_MSG_SRVR = 0
    AUTH_MSG_CLNT = 1
    INIT_MSG = 2

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.mutual_key = "password"
        self.challenge = os.random(16)
        self.df = None


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # "I'm Alice" + Ra
        # (Init) -> Waiting for server message
        return  {
                "type": "key_exchange_init",
                "data": {
                    "challenge": self.challenge,
                        }
                }
        


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # receiving message is always a protocol message if state is not established
        return self.state != self.ESTABLISHED


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # <ID>,<Rc>          MSG_TYPE:INIT       (Init) -> Waiting for client message
        # <Es>,<Hs>,<Rs>     MSG_TYPE:AUTH       (Client: Waiting for server message) -> Established
        # <Ec>,<Hc>,<Rc>     MSG_TYPE:AUTH       (Server: Waiting for client message) - > Established

        sendMsg = None
 
        if self.state == self.INIT:
            if message['type'] == 'key_exchange_init':
                # Send AuthMsg Srv
                self.df = DiffiHellman()
                sendMsg = self._createSendMessage(message, self.AUTH_MSG_SRVR)
                self.state = self.WAIT_FOR_CLIENT
            else:
                print("Error") # error state failed logic
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_CLIENT:
            if message['type'] == 'key_exchange_clnt':
                # Don't send msg
                if self.verify(message):
                    self.SetSessionKey(message)
                    self.state = self.ESTABLISHED
                else: 
                    sendMsg = self._createSendMessage(message, self.ERROR)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_SERVER:
            self.df = DiffiHellman()
            if message['type'] == 'key_exchange_srv':
                if self.verify(message):
                    sendMsg = self._createSendMessage(self.AUTH_MSG_SRVR, message)
                    self.SetSessionKey(message)
                    self.state = self.ESTABLISHED
            else:
                print("Error")
                sendMsg = self._createSendMessage(message, self.ERROR)
                self.state = self.INIT


        return sendMsg


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self. = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text

    def _createSendMessage(self, MSG_TYPE, receivedMsg = ""):
        # Based on the state create sending protocol message
        # INIT: <ID>,<R>
        # WAIT_FOR_CLIENT: <E("SRVR",g^a mod p,R>,H(..),R
        # WAIT_FOR_SERVER: <E("SRVR",g^a mod p,R>,H(..),R

        if MSG_TYPE == self.INIT_MSG:
            self.nonce = os.urandom(16)
            response = {
                "type": "key_exchange_init",
                "data": {
                    "challenge": self.nonce.hex(),
                }
            }
            
        if MSG_TYPE == self.AUTH_MSG_SRVR:
            response = {
            "type": "key_exchange_clnt",
            "encrypted": self.encrypt(self.df.A, receivedMsg['data']['challenge'], self.mutual_key),
            "challenge": self.challenge
        }
            
        if MSG_TYPE == self.AUTH_MSG_CLNT:
            response = {
            "type": "key_exchange_clnt",
            "encrypted": self.encrypt(self.df.A, receivedMsg['data']['challenge'], self.mutual_key)
        } 
        


        return response




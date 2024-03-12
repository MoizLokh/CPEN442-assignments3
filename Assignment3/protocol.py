import os
import json


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
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        # receiving message is always a protocol message if state is not established
        try:
            jsonMsg = json.loads(message)
            isProto = any([jsonMsg["type"] == ("key_exchange_"+x) for x in ["init", "clnt", "srvr"]])
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)
            isProto = False

        return isProto


    # Processing protocol message
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # <ID>,<Rc>          MSG_TYPE:INIT       (Init) -> Waiting for client message
        # <Es>,<Hs>,<Rs>     MSG_TYPE:AUTH       (Client: Waiting for server message) -> Established
        # <Ec>,<Hc>,<Rc>     MSG_TYPE:AUTH       (Server: Waiting for client message) - > Established

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

            if jsonMsg["type"] == "key_exchange_clnt" and verified:
                # Don't send msg
                self.dh.compSK(decriptJson["dh"])
                self.SetSessionKey(self.dh.SK)
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_SERVER:
            decriptJson, verified = self.decrypt(jsonMsg["encrypted"])

            if jsonMsg["type"] == "key_exchange_srvr" and verified:
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


    # Setting the key for the current session
    def SetSessionKey(self, key):
        self._key = key
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

    def _setStateTo(self, next_state):
        if self.Verbose:
            print(self.state + " --> " + next_state)
        self.state = next_state

    def _createSendMessage(self, MSG_TYPE, receivedChallenge = ""):
        response = None

        if MSG_TYPE == self.INIT_MSG:
            response = {
                "type": "key_exchange_init",
                "challenge": self.challenge
            }
            
        if MSG_TYPE == self.AUTH_MSG_SRVR:
            response = {
                "type": "key_exchange_clnt",
                "encrypted": self.encrypt(self.df.A, receivedChallenge),
                "challenge": self.challenge
            }
            
        if MSG_TYPE == self.AUTH_MSG_CLNT:
            response = {
                "type": "key_exchange_clnt",
                "encrypted": self.encrypt(self.df.A, receivedChallenge)
            }

        return response

    # TODO: Return a random challenge for the current node instance
    def _createNewChallenge(self):
        return ""




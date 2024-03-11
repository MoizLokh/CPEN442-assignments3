class Messages:
    def __init__(self, message):
        self.msg = message
        self.challenge = ""
        self._parseMsg()
    pass

    def _parseMsg(self):
        pass

class InitMessage(Messages):
    def __init__(self, message):
        self.id = ""
        Messages.__init__(self, message)

    def _parseMsg(self):
        # <ID>,<R>
        words = self.msg.split(',')
        self.id = words[0]
        self.challenge = words[1]

class AuthMessage(Messages):
    SERVER = 0
    CLIENT = 1

    def __init__(self, message):
        self.encryptMsg = ""
        self.DH = 0
        self.hash = ""
        self.msgType = self.SERVER

        Messages.__init__(self, message)

    def verifyMsg(self):
        # Decript and compare hash
        return True

    def _parseMsg(self):
        # <E("SRVR/CLNT",g^a mod p,Ra>,H(..),Rb
        words = self.msg.split(',')
        self.encryptMsg = words[0]
        self.DH = words[1]
        self.challenge = words[2]


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
        self.state = self.INIT
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # "I'm Alice" + Ra
        # (Init) -> Waiting for server message
        self._setStateTo(self.WAIT_FOR_SERVER)
        return self._createSendMessage(self.INIT_MSG)


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

        sendMsg = ""
        parsedMsg = self._getParsedMessage(message)

        if self.state == self.INIT:
            if isinstance(parsedMsg, InitMessage):
                # Send AuthMsg Srv
                sendMsg = self._createSendMessage(self.AUTH_MSG_SRVR, parsedMsg)
                self._setStateTo(self.WAIT_FOR_CLIENT)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_CLIENT:
            if isinstance(parsedMsg, AuthMessage) and parsedMsg.verifyMsg():
                # Don't send msg
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                self._setStateTo(self.INIT)

        elif self.state == self.WAIT_FOR_SERVER:
            if isinstance(parsedMsg, AuthMessage) and parsedMsg.verifyMsg():
                # Send AuthMsg client
                sendMsg = self._createSendMessage(self.AUTH_MSG_CLNT, parsedMsg)
                self._setStateTo(self.ESTABLISHED)
            else:
                print("Error")
                self._setStateTo(self.INIT)


        return sendMsg


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
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

    def _getParsedMessage(self, message):
        # Messages class parses the message and stores the data, TODO: Return the right type (InitMessage, AuthMessage) depending on message/state
        return Messages(message)

    def _createSendMessage(self, MSG_TYPE, receivedMsg = ""):
        # Based on the state create sending protocol message
        # INIT: <ID>,<R>
        # WAIT_FOR_CLIENT: <E("SRVR",g^a mod p,R>,H(..),R
        # WAIT_FOR_SERVER: <E("SRVR",g^a mod p,R>,H(..),R

        if MSG_TYPE == self.INIT_MSG:
            response = {
                "type": "init",
                "data": {
                    
                }
            }

        return ""




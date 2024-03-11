import random
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
    def __init__(self, message):
        self.encryptMsg = ""
        self.DH = 0
        self.hash = ""
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
        return ""


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

        parsedMsg = self._getParsedMessage(message)

        if isinstance(parsedMsg, InitMessage):
            if self.state != self.INIT:
                # return error and reset state to INIT
                self._setStateTo(self.INIT)
                return

            self._setStateTo(self.WAIT_FOR_CLIENT)

        elif isinstance(parsedMsg, AuthMessage):
            if parsedMsg.verifyMsg():
                if self.state != self.WAIT_FOR_CLIENT or self.state != self.WAIT_FOR_SERVER:
                    # return error and reset state to INIT
                    self._setStateTo(self.INIT)

                self._setStateTo(self.ESTABLISHED)

        return self._getProtoSendingMessage(parsedMsg)


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

    def _getProtoSendingMessage(self, receivedMsg):
        # Based on the state create sending protocol message
        # INIT: <ID>,<R>
        # WAIT_FOR_CLIENT: <E("SRVR",g^a mod p,R>,H(..),R
        # WAIT_FOR_SERVER: <E("SRVR",g^a mod p,R>,H(..),R

        return ""
    
class DiffieHellman:
    def __init__(self, p, g):
        self._p = p # large prime
        self._g = g # primitive root of it (Will probably go for something small)

    def generate_keys(self):
        priv_key = random.randint(2, self._p-2)
        pub_key = pow(self._g, priv_key, self._p)
        return priv_key, pub_key   
     
    def generate_shared_secret(self, own_priv_key, other_pub_key):
        return pow(other_pub_key, own_priv_key, self._p) # session key






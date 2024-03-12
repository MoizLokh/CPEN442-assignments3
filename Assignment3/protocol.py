from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    KEY_LENGTH=16
    def __init__(self):
        # Assume key is a fixed 128-bit (16 byte) size - can hash to ensure this
        self._session_key = None


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        return ""


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._session_key = key
        pass

    
    # For encryption and decryption we can AES as it is a popular symmetric block cipher and trusted to be secure
    # Mode EAX as show in documentation: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html also 
    # provides integrity checking to ensure message is not garbled

    # This function is to be used specifically for encrypting messages after mutual authentication is done
    def EncryptAndProtectMessage(self, plain_text):
        # See example from: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        print(f"Encryption says: {plain_text}")

        # EAX mode requires nonce and also produces tag for integrity checking
        nonce = get_random_bytes(Protocol.KEY_LENGTH)
        AES_cipher = AES.new(key=self._session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.KEY_LENGTH)
        ciphertext, mac_tag = AES_cipher.encrypt_and_digest(plain_text.encode())

        # Combine all messages into one
        cipher_text_combined = nonce+ciphertext+mac_tag
        print(f"Encryption says: {cipher_text_combined}")
        return cipher_text_combined


    # This function is to be used specifically for decrypting messages after mutual authentication is done
    def DecryptAndVerifyMessage(self, cipher_text):
        print(f"Decryption says: {cipher_text}")

        # Extract nonce, message, and tag in that order
        nonce = cipher_text[:Protocol.KEY_LENGTH]
        encrypted_message = cipher_text[Protocol.KEY_LENGTH:-Protocol.KEY_LENGTH]
        mac_tag = cipher_text[-Protocol.KEY_LENGTH:]

        # Do verification and decryption
        AES_cipher = AES.new(key=self._session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.KEY_LENGTH)

        try:
            message = AES_cipher.decrypt_and_verify(encrypted_message, mac_tag)
            print("Message integrity verified, tag does match!")
            return message
        except ValueError:
            print("Message integrity has been compromised, tag does not match!")

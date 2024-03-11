import os
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ProtocolStates:
    INIT = "INIT"
    WAIT_FOR_CLIENT = "WAIT_FOR_CLIENT"
    SESSION_KEY_ESTABLISHED = "SESSION_KEY_ESTABLISHED"
    
class Protocol:
    def __init__(self):
        self.state = ProtocolStates.INIT
        self.session_key = None
        self.nonce = None
        self.public_key = None
        self.private_key = None
        self.mutual_key = None # common and secure mutual key
        
        self.g = 2  # A common choice for g in practice
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6D3B8BCECFAA593B150A4B35BF3932D27FFFFFFFFFFFFFFFF  # A common 2048-bit safe prime for p
        self.secret_key = os.urandom(32)  
        

    def hash_data(self, data):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.encode())
        return digest.finalize()
        
    def encrypt_data_with_mutual_key(self, data_to_encrypt, mutual_key):
        # Derive a key from the mutual key 
        salt = os.urandom(16)  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, 
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(mutual_key)  # Derive a secure key from the mutual_key

        # Encrypt the data
        iv = os.urandom(16)  # Initialization vector for AES
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_to_encrypt.encode()) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data

    def ProcessReceivedProtocolMessage(self, received_message):
        # Parse message
        message = json.loads(received_message)
        if 'type' not in message or 'data' not in message:
            pass # TODO handle error

        if self.state == ProtocolStates.INIT:
            if message['type'] == 'key_exchange_init':
                # Server sends response and Transition to WAIT_FOR_CLIENT
                response = self.handle_key_exchange_init(message)
            elif message['type'] == 'key_exchange_srv':
                # Client verifies conditions, establish key if valid, move to SESSION_KEY_ESTABLISHED
                response = self.handle_key_exchange_srv(message)

        elif self.state == ProtocolStates.WAIT_FOR_CLIENT:
            if message['type'] == 'key_exchange_clnt':
                # Server verifies message, establish key, and transition to SESSION_KEY_ESTABLISHED
                response = self.handle_key_exchange_clnt(message)

        elif self.state == ProtocolStates.SESSION_KEY_ESTABLISHED:
            pass
        
        else :
            pass # TODO handle error
        
        return response

    # Implement handlers for each message type/state
    def handle_key_exchange_init(self, message):
        
        self.nonce = os.urandom(16)
        diffieHellmanPub = pow(self.g, int.from_bytes(self.secret_key, "big"), self.p)
        data_to_encrypt = f"{diffieHellmanPub},{self.nonce.hex()}"
        sessionKeyEnc = self.encrypt_data_with_mutual_key(data_to_encrypt, self.mutualKey)
        hash_of_sessionKeyEnc = hashlib.sha256(sessionKeyEnc).hexdigest()

        response = {
            "type": "key_exchange_response",
            "data": {
                "nonce": self.nonce.hex(),
                "sessionKeyEnc": sessionKeyEnc.hex(),
                "hash": hash_of_sessionKeyEnc,
                "g": self.g,
                "p": self.p
            }
        }

        response_json = json.dumps(response)
        
        self.state = ProtocolStates.WAIT_FOR_CLIENT

    def handle_key_exchange_srv(self, message):
        pass

    def handle_key_exchange_clnt(self, message):
        pass

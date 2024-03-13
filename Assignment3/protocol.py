from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Random import get_random_bytes

from DHKeyExchange import DH

class Protocol:
    # Initializer (Called from app.py)
    KEY_LENGTH=16
    TAG_LENGTH=16
    CHALLENGE_LENGTH=16
    CLNT="CLNT"
    SRVR="SRVR"
    PROTO_MESSAGE="TYPE_P"
    REGULAR_MESSAGE="TYPE_M"
    PROTO_ID_LENGTH=6
    CODE_NAME_LENGTH=4

    def __init__(self):
        # Assume key is a fixed 128-bit (16 byte) size - can hash to ensure this
        self._key = b'X1#\x0e=\xea\x1b\xb4H\xce\xbcP\xb1\xaf\x8e9'
        self.own_challenge = None


    # Returns: [TYPE_P | CLNT | Random_challenge] - utf-8 encoded length of 6+4+16 = 26 bytes
    def GetProtocolInitiationMessage(self):
        self.own_challenge = self.generate_challenge(Protocol.CHALLENGE_LENGTH)
        print(f"Client generated challenge: {self.own_challenge}")
        return Protocol.PROTO_MESSAGE.encode() + Protocol.CLNT.encode() + self.own_challenge


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        if message[:Protocol.PROTO_ID_LENGTH] == Protocol.PROTO_MESSAGE.encode():
            return True
        else:
            return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, master_key, op_mode, conn):
        if op_mode == 0:
            print(f"Operating as client")
            self._client_mode_auth(message, master_key, conn)
        else:
            print(f"Operating as server")
            self._server_mode_auth(message, master_key, conn)


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = self.fix_key_length(key)

    
    # For encryption and decryption we can AES as it is a popular symmetric block cipher and trusted to be secure
    # Mode EAX as show in documentation: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html also 
    # provides integrity checking to ensure message is not garbled

    # This function is to be used specifically for encrypting messages after mutual authentication is done
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


    # This function is to be used specifically for decrypting messages after mutual authentication is done
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

    def generate_challenge(self, length):
        return get_random_bytes(length)
    
    # In client mode we receive a message like so in byte stream format:
    # TYPE_P + Nonce (16 bytes) + Ciphertext (unknown) + Tag (16 bytes) + Challenge (16 bytes)
    def _client_mode_auth(self, message, key, conn):
        # print(f"Client got {message}")

        nonce = message[Protocol.PROTO_ID_LENGTH:Protocol.PROTO_ID_LENGTH+Protocol.KEY_LENGTH]
        received_challenge = message[-Protocol.CHALLENGE_LENGTH:]
        mac_tag = message[-Protocol.CHALLENGE_LENGTH-Protocol.TAG_LENGTH:-Protocol.CHALLENGE_LENGTH]
        cipher_text = message[Protocol.PROTO_ID_LENGTH+Protocol.KEY_LENGTH: -Protocol.CHALLENGE_LENGTH-Protocol.TAG_LENGTH]
        # print(nonce)
        # print(cipher_text)
        # print(mac_tag)
        # print(challenge)

        AES_cipher = AES.new(key=self.fix_key_length(key), mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)

        try:
            message = AES_cipher.decrypt_and_verify(cipher_text, mac_tag)
            print("Message integrity verified, tag does match!")

            # Verify the server solved the challenge correctly
            solved_challenge = message[Protocol.CODE_NAME_LENGTH:Protocol.CODE_NAME_LENGTH+Protocol.CHALLENGE_LENGTH]
            if solved_challenge != self.own_challenge:
                raise ValueError("Server did not solve challenge correctly")
            
            print("Server solved challenge correctly")
            
            diffie_h = DH()

            # Establish session key
            server_public_key = message[Protocol.CODE_NAME_LENGTH+Protocol.CHALLENGE_LENGTH:]
            shared_session_key = diffie_h.generate_shared_session_key(int(server_public_key.decode()))
            self.SetSessionKey(str(shared_session_key))
            print(f"Set session key to: {self._key}")

            # Encrypt challenge received from server and send own public key from Diffie Hellman
            # The message looks as follows TYPE_P | Encrypt(CLNT | Random_challenge | DH_public)

            nonce = get_random_bytes(Protocol.KEY_LENGTH)
            AES_cipher = AES.new(key=self.fix_key_length(key), mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)
            plain_text = Protocol.CLNT.encode() + received_challenge + str(diffie_h.public_key).encode()
            ciphertext, mac_tag = AES_cipher.encrypt_and_digest(plain_text)

            clnt_msg = nonce + ciphertext + mac_tag
            conn.send(clnt_msg)


        except ValueError:
            print("Message integrity has been compromised, tag does not match!")


    # In server mode we have just received the following: [TYPE_P | CLNT | Random_challenge]
    # The goal is to send back Encr(SRVR|Random_challenge|DH_public)|Random_challenge
    def _server_mode_auth(self, message, key, conn):
        received_challenge = message[-Protocol.CHALLENGE_LENGTH:]

        # Create own challenge and save it to get it ready for verification
        random_challenge = self.generate_challenge(Protocol.CHALLENGE_LENGTH)
        print(f"Server generated challenge: {random_challenge}")
        self.own_challenge = random_challenge
        
        diffie_h = DH()

        # Construct plaintext which is already encoded
        plain_text = Protocol.SRVR.encode() + received_challenge + str(diffie_h.public_key).encode()
        print(type(plain_text))

        nonce = get_random_bytes(Protocol.KEY_LENGTH)
        AES_cipher = AES.new(key=self.fix_key_length(key), mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)
        ciphertext, mac_tag = AES_cipher.encrypt_and_digest(plain_text)

        # Send over the network
        server_msg = Protocol.PROTO_MESSAGE.encode() + nonce + ciphertext + mac_tag + random_challenge
        conn.send(server_msg)

        clnt_msg = conn.recv(4096)
        print(f"Received: {clnt_msg}")
        # TODO: Last step of completing mutual authentication here, where we receive the message from the client

        nonce = clnt_msg[:Protocol.KEY_LENGTH]
        encrypted_message = clnt_msg[Protocol.KEY_LENGTH:-Protocol.TAG_LENGTH]
        mac_tag = clnt_msg[-Protocol.TAG_LENGTH:]

        AES_cipher = AES.new(key=self.fix_key_length(key), mode=AES.MODE_GCM, nonce=nonce, mac_len=Protocol.TAG_LENGTH)

        try:
            decrypted_message = AES_cipher.decrypt_and_verify(encrypted_message, mac_tag)
            print("Message integrity verified, tag does match!")
            received_challenge = decrypted_message[Protocol.CODE_NAME_LENGTH:Protocol.CODE_NAME_LENGTH+Protocol.CHALLENGE_LENGTH]
            if random_challenge != received_challenge:
                raise ValueError("Client did not solve challenge correctly")
            
            client_public_key = decrypted_message[Protocol.CODE_NAME_LENGTH+Protocol.CHALLENGE_LENGTH:]
            shared_session_key = diffie_h.generate_shared_session_key(int(client_public_key.decode()))
            self.SetSessionKey(str(shared_session_key))
            print(f"Set session key to: {self._key}")
        except ValueError:
            print("Message integrity has been compromised, tag does not match!")


    def fix_key_length(self, key):
        hashFn = SHAKE128.new()
        hashFn.update(key.encode())
        return hashFn.read(Protocol.KEY_LENGTH)

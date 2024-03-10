from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)
class Protocol:
    KEY_LENGTH=16

def EncryptAndProtectMessage(plain_text):
    # See example from: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    print(f"Encryption says: {plain_text}")

    # EAX mode requires nonce and also produces tag for integrity checking
    nonce = get_random_bytes(Protocol.KEY_LENGTH)
    AES_cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce, mac_len=Protocol.KEY_LENGTH)
    ciphertext, mac_tag = AES_cipher.encrypt_and_digest(plain_text.encode())

    print(nonce)
    print(ciphertext)
    print(mac_tag)
    
    # Combine all messages into one
    cipher_text_combined = nonce+ciphertext+mac_tag
    print(f"Encryption says: {cipher_text_combined}")
    return cipher_text_combined

def DecryptAndVerifyMessage(cipher_text):
    print(f"Decryption says: {cipher_text}")

    # Extract nonce, message, and tag in that order
    nonce = cipher_text[:Protocol.KEY_LENGTH]
    encrypted_message = cipher_text[Protocol.KEY_LENGTH:-Protocol.KEY_LENGTH]
    mac_tag = cipher_text[-Protocol.KEY_LENGTH:]
    print(nonce)
    print(encrypted_message)
    print(mac_tag)

    # Do verification and decryption
    AES_cipher = AES_cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce, mac_len=Protocol.KEY_LENGTH)
    message = None
    try:
        message = AES_cipher.decrypt_and_verify(encrypted_message, mac_tag)
        print("Message integrity verified, tag does match!")
    except ValueError:
        print("Message integrity has been compromised, tag does not match!")
        
    return message.decode()

messgae = "No because this is some next level bullshit"
encrypted = EncryptAndProtectMessage(messgae)
print(type(encrypted))
print(encrypted)
decrypted = DecryptAndVerifyMessage(encrypted)
print(type(decrypted))
print(decrypted)


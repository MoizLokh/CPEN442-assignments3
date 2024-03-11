from protocol import DiffieHellman

df = DiffieHellman(162259276829213363391578010288127,2)

a, A = df.generate_keys()
print("Alice's private key (a):", a)
print("Alice's public key (A):", A)

b, B = df.generate_keys()
print("Bob's private key (b):", b)
print("Bob's public key (B):", B)

shared_secret_Alice = df.generate_shared_secret(a, B)
shared_secret_Bob = df.generate_shared_secret(b, A)

print("Shared secret computed by Alice:", shared_secret_Alice)
print("Shared secret computed by Bob:", shared_secret_Bob)
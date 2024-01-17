import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

    def decrypt(self, data):
        iv = data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)

def generate_nonce():
    return random.SystemRandom().randint(0, 99999999)

# Keys and Messages Generation
key_bob_server = get_random_bytes(16)
key_alice_bob = get_random_bytes(16)
cipher_bob_server = AESCipher(key_bob_server)
cipher_alice_bob = AESCipher(key_alice_bob)

alice_message = f"{key_alice_bob.hex()},Alice".encode()
encrypted_message = cipher_bob_server.encrypt(alice_message)

# Display Keys and Messages
print("Unknown to Eve:")
print("Pre-shared key between Alice and Server: [does not matter / Unused in the attack]")
print(f"Pre-shared key between Bob and Server: {key_bob_server.hex()}")

print("\nKnown to Eve (Collected from a previous session between Alice and Bob):")
print(f"Pre-recorded K_AB: {key_alice_bob.hex()}")
print(f"Pre-recorded Message 3 (Alice => Bob): {encrypted_message.hex()}")

# Bob's Simulation
try:
    decrypted_message = cipher_bob_server.decrypt(encrypted_message)
    session_key_hex, alice_check = decrypted_message.decode().split(',')

    if alice_check != "Alice":
        raise Exception("Failed to authenticate Alice")

    print(f"\n3 (Eve => Bob): E_{{K_BS}} (K_AB, A) = {encrypted_message.hex()}")
    print(f"3 (Bob): (K_AB, A) = ({session_key_hex}, Alice)")
    print("Eve successfully passed message 3 authentication!")

    nonce_bob = generate_nonce()
    encrypted_nonce = cipher_alice_bob.encrypt(str(nonce_bob).encode())
    print(f"4 (Bob): N_B = {nonce_bob}")
    print(f"4 (Bob => Eve): E_{session_key_hex} (N_B) = {encrypted_nonce.hex()}")

    decrypted_nonce = cipher_alice_bob.decrypt(encrypted_nonce)
    nonce_received = int(decrypted_nonce.decode())
    print(f"4 (Eve): N_B = {nonce_received}")
    print("Eve successfully decrypted Message 4 to get N_B!")

    nonce_response = nonce_received - 1
    encrypted_response = cipher_alice_bob.encrypt(str(nonce_response).encode())
    print(f"5 (Eve => Bob): E_{session_key_hex} (N_B-1) = {encrypted_response.hex()}")

    decrypted_response = cipher_alice_bob.decrypt(encrypted_response)
    nonce_response_received = int(decrypted_response.decode())

    if nonce_response_received != nonce_bob - 1:
        raise Exception("Nonce mismatch detected")

    print(f"5 (Bob): N_B-1 = {nonce_response_received}")
    print("Eve successfully passed Message 5 authentication!\n")
    print("Eve successfully launched a replay attack to reuse a previously recorded session key agreed between Alice and Bob.")

except Exception as e:
    print(f"Error occurred: {e}")

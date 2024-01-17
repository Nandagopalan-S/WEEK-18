import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint

def generate_key():
   #Generate and return a random 16-byte key
    return get_random_bytes(16)

def encrypt(message, key):
   #Encrypt the message using AES in CBC mode with the given key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + ct_bytes

def decrypt(ciphertext, key):
    #Decrypt the ciphertext using AES in CBC mode with the given key
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Initialization of keys
K_AS = generate_key()  # Alice-Server key
K_BS = generate_key()  # Bob-Server key
K_AB = generate_key()  # Alice-Bob session key

print(f"Pre-shared key between Alice and Server: {K_AS.hex()}")
print(f"Pre-shared key between Bob and Server: {K_BS.hex()}")

print("\n=== Needham-Schroeder Protocol Simulation ===\n")

# Alice initiates the protocol
N_A = randint(0, 99999999)
print(f"1 (Alice): N_A {N_A}")
print(f"1 (Alice > Server): (A, B, N_A) (Alice, Bob, {N_A})")

# Server's response to Alice
message_for_Alice = f"{N_A},{K_AB.hex()}".encode()
encrypted_msg_for_Alice = encrypt(message_for_Alice, K_AS)
print(f"2 (Server): K_AB {K_AB.hex()}")
print(f"2 (Server): Encrypted (N_A, K_AB) = {encrypted_msg_for_Alice.hex()}")

# Alice decrypts Server's message
try:
    decrypted_msg_for_Alice = decrypt(encrypted_msg_for_Alice, K_AS)
    N_A_received, K_AB_received_hex = decrypted_msg_for_Alice.decode().split(',')
    assert int(N_A_received) == N_A, "Nonce mismatch. Replay attack suspected."
    print(f"2 (Alice): Decrypted (N_A, B, K_AB, E(K_BS) (K_AB, A)) = ({N_A_received}, Bob, {K_AB_received_hex}, [encrypted part])")
    print("=> Alice's authentication successful")

    # Prepare and encrypt Alice's message to Bob
    message_for_Bob = f"{K_AB_received_hex},Alice".encode()
    encrypted_message_for_Bob = encrypt(message_for_Bob, K_BS)
    print(f"3 (Alice -> Bob): Encrypted (K_AB, A) = {encrypted_message_for_Bob.hex()}")
except Exception as e:
    print(f"Error at Alice's side: {e}")
    sys.exit()

# Bob decrypts Alice's message
try:
    decrypted_message_for_Bob = decrypt(encrypted_message_for_Bob, K_BS)
    K_AB_for_Bob_hex, Alice_identifier = decrypted_message_for_Bob.decode().split(',')
    assert Alice_identifier == "Alice", "Alice identifier not found. Authentication failed."
    print(f"3 (Bob): Decrypted (K_AB, A) = ({K_AB_for_Bob_hex}, Alice)")
    print("=> Bob's authentication successful")
# Bob's nonce challenge to Alice
    N_B = randint(0, 99999999)
    encrypted_nonce_for_Alice = encrypt(str(N_B).encode(), bytes.fromhex(K_AB_for_Bob_hex))
    print(f"4 (Bob -> Alice): Encrypted (N_B) = {encrypted_nonce_for_Alice.hex()}")

except Exception as e:
    print(f"Error at Bob's side: {e}")
sys.exit()

try:
 decrypted_nonce_for_Alice = decrypt(encrypted_nonce_for_Alice, bytes.fromhex(K_AB_for_Bob_hex))
 N_B_received = int(decrypted_nonce_for_Alice.decode())
 assert N_B_received == N_B, "Nonce mismatch. Replay attack suspected."
 N_B_response = N_B_received - 1
 encrypted_response_for_Bob = encrypt(str(N_B_response).encode(), bytes.fromhex(K_AB_for_Bob_hex))
 print(f"5 (Alice -> Bob): Encrypted (N_B-1) = {encrypted_response_for_Bob.hex()}")

except Exception as e:
 print(f"Error at Alice's side responding to Bob: {e}")
sys.exit()

try:
 decrypted_response_for_Bob = decrypt(encrypted_response_for_Bob, bytes.fromhex(K_AB_for_Bob_hex))
 N_B_decremented_received = int(decrypted_response_for_Bob.decode())
 assert N_B_decremented_received == N_B - 1, "Nonce response mismatch. Replay attack suspected."
 print(f"5 (Bob): Verified N_B-1 = {N_B_decremented_received}")
 print("=> Bob's verification successful")
 print(f"The key agreed between Alice and Bob: {K_AB.hex()}")

except Exception as e:
 print(f"Error at Bob's side verifying Alice's response: {e}")
sys.exit()




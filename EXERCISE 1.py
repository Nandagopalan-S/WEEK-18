import hmac
import hashlib
import secrets

def generate_random_key(length):
  # Generates a random secret key of a specified length.
    return secrets.token_hex(length)

def generate_16bit_hmac(message, key):
    #Generates a 16-bit HMAC for a given message and key.
    
    hmac_gen = hmac.new(key.encode(), message.encode(), hashlib.sha256)
    return hmac_gen.digest()[:2]

def brute_force_hmac(target_hmac, message, key_length):
    #Brute-forces to find a key that generates an HMAC matching the target HMAC.
    attempts = 0
    while True:
        attempts += 1
        random_key = generate_random_key(key_length)
        test_hmac = generate_16bit_hmac(message, random_key)
        if test_hmac == target_hmac:
            break
    return attempts

# Original and tampered messages
original_message = "Alice, Bob, £10"
tampered_message = "Alice, Eve, £1000"

# Generate a random secret key
key = generate_random_key(16)  # 16 bytes key

# Generate HMAC for the original message
original_hmac = generate_16bit_hmac(original_message, key)
# Brute-force to find a key that generates the same HMAC for the tampered message
attempts_needed = brute_force_hmac(original_hmac, tampered_message, 16)

# Output
print("Original Message:", original_message)
print("Original HMAC:", original_hmac.hex())
print("Tampered Message:", tampered_message)
print("Estimated brute-force attempts needed:", attempts_needed)

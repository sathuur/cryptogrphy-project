# Block Cipher Code

# S-box for substitution
s_box = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]

def substitute_4bit(input_4bit):
    return s_box[input_4bit]

def permute_8bit(block):
    permutation_table = [1, 5, 2, 0, 3, 7, 4, 6]
    permuted_block = 0
    for i, new_pos in enumerate(permutation_table):
        bit = (block >> i) & 1
        permuted_block |= (bit << new_pos)
    return permuted_block

def feistel_function(block, key):
    xor_result = block ^ key
    return substitute_4bit(xor_result)

def feistel_round(block, key):
    left_half = (block >> 4) & 0xF
    right_half = block & 0xF
    new_left = left_half ^ feistel_function(right_half, key & 0xF)
    encrypted_block = (right_half << 4) | new_left
    return permute_8bit(encrypted_block)

def ecb_encrypt(plaintext, key):
    return [feistel_round(block, key) for block in plaintext]

def ecb_decrypt(ciphertext, key):
    return [feistel_round(block, key) for block in ciphertext]

def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    previous_block = iv
    for block in plaintext:
        xor_block = block ^ previous_block
        encrypted_block = feistel_round(xor_block, key)
        ciphertext.append(encrypted_block)
        previous_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    previous_block = iv
    for block in ciphertext:
        decrypted_block = feistel_round(block, key)
        plaintext_block = decrypted_block ^ previous_block
        plaintext.append(plaintext_block)
        previous_block = block
    return plaintext

# Sample usage
plaintext = [0b11001010]
key = 0b10101010
iv = 0b11110000

# ECB Mode
ciphertext_ecb = ecb_encrypt(plaintext, key)
decrypted_ecb = ecb_decrypt(ciphertext_ecb, key)

# CBC Mode
ciphertext_cbc = cbc_encrypt(plaintext, key, iv)
decrypted_cbc = cbc_decrypt(ciphertext_cbc, key, iv)

print(f'ECB Encrypted: {ciphertext_ecb}')
print(f'ECB Decrypted: {decrypted_ecb}')
print(f'CBC Encrypted: {ciphertext_cbc}')
print(f'CBC Decrypted: {decrypted_cbc}')
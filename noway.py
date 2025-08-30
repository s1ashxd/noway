import base58
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
def lzw_decompress(compressed):
    dictionary = {i: chr(i) for i in range(256)}
    next_code = 256
    result = []
    codes = [int.from_bytes(compressed[i:i + 2], byteorder='big') for i in range(0, len(compressed), 2)]
    if not codes:
        return ""
    current = codes[0]
    if current not in dictionary:
        raise ValueError(f"wrong start code: {current}")
    result.append(dictionary[current])
    for code in codes[1:]:
        if code in dictionary:
            entry = dictionary[code]
        else:
            if code != next_code:
                raise ValueError(f"wrong code: {code}")
            entry = dictionary[current] + dictionary[current][0]
        result.append(entry)
        dictionary[next_code] = dictionary[current] + entry[0]
        next_code += 1
        current = code
    return ''.join(result)
data = base58.b58decode(input("nonce:salt:ciphertext:hmac: ")).decode().split(':')
try:
    nonce = base58.b58decode(data[0])
    salt = base58.b58decode(data[1])
    ciphertext = base58.b58decode(data[2])
    hmac_received = base58.b58decode(data[3])
except Exception as e:
    print(f"b64 error: {e}")
    exit(1)
passphrase = input("passphrase: ")
key = PBKDF2(passphrase, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
hmac_calculated = HMAC.new(key, ciphertext, SHA256).digest()
if hmac_calculated != hmac_received:
    print("hmac error: hmac check failed, data is corrupted")
    exit(1)
try:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    compressed = cipher.decrypt(ciphertext)
except Exception as e:
    print(f"aes error: {e}")
    exit(1)
try:
    plaintext = lzw_decompress(compressed)
except Exception as e:
    print(f"lzw error: {e}")
    exit(1)
with open('output.txt', 'w', encoding='utf-8') as f:
    words = plaintext.split()
    if len(words) % 12 == 0:
        for i in range(0, len(words), 12):
            f.write(' '.join(words[i:i + 12]) + '\n')
    else:
        f.write(plaintext)
print("done: output.txt")

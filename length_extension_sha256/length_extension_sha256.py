import hashlib
import hexdump
import struct

# https://github.com/Akif-G/sha256
import sha256

KEY = b"KEYVALUE"

EXPECTED_KEY_LEN = 32
ORIGIN_STRING = b"This Is An Original Data"
INJECT_STRING = "I'm Attacker"

class Sha256Padding:
    def __init__(self):
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    # TODO: If the pad method same with sha1's thing, write the comment here
    def pad(self, message):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        return message

def client():
    h = hashlib.new('sha256')
    h.update(KEY)
    h.update(ORIGIN_STRING)
    
    return ORIGIN_STRING, h.hexdigest()

def server(data, hashValue):
    h = hashlib.new('sha256')
    h.update(KEY + data)

    if (hashValue == h.hexdigest()):
        print("-- Server --")
        print("Server - I've received data:", data)
        print("Server - I've recevied hash:", hashValue)
        print("Server - Also I've calculateed the hash with secret key:", h.hexdigest())
        return True
    else:
        return False

def attack(originData, originHash, keyLen):

    """ Generate attackData """
    # Padding - (KEY + originData + padding) + attackData
    pad = Sha256Padding()

    tmpStr = ('A' * keyLen).encode()
    attackData = pad.pad(tmpStr + originData)[keyLen:] + INJECT_STRING.encode()
    #print(hexdump.hexdump(attackData))

    """ Generate attackHash """
    sha = sha256.Sha256(INJECT_STRING, originHash.encode())
    attackHash = sha.sha256
    
    return attackData, attackHash

def main():
    print("-----Client-----")
    originData, originHash = client()
    server(originData, originHash)

    print("-----Attacker-----")
    for keyLen in range(0, EXPECTED_KEY_LEN):
        attackData, attackHash = attack(originData, originHash, keyLen)
        if(server(attackData, attackHash) is True):
            print("keyLen:", keyLen)
            break

if __name__ == "__main__":
    main()

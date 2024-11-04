import hashlib
import zlib
import random
import base64
import rings
from datetime import datetime
from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad

#parametri koji se cuvaju zbog dekripcije
tripleDESKeyParams = []
tripleDESKeys = []
tripleDESPermsI = []
tripleDESExpands = []
tripleDESPerms = []
cast_key = []
cast_iv = []

def hashMessage(message, time):
    message += time
    encodedMessage = message.encode('UTF-8')
    hash = hashlib.sha1(encodedMessage)
    digest = hash.hexdigest()
    return digest

def leadingOctets(digest):
    digestStr = str(digest)[2:]
    if len(digestStr) < 4:
        return 0
    return digestStr[0:4]

def signMessage(d, n, message, key_id):
    time = str(datetime.now())
    digest = hashMessage(message, time)
    signature = pow(int(digest, 16), d, n)
    leading = leadingOctets(hex(signature))
    signature = str(hex(signature))[2:]

    #trazeni format potpisa poruke
    messageSignature = "_" + time + "_" + key_id + "_" + leading + "_" + signature
    return messageSignature

def signRequest(d, n, message, key_id):
    #poruka je u formatu sadrzaj_vreme_imeFajla; potpisuje se samo sadrzaj
    return message + signMessage(d, n, message.split("_")[0], key_id)

def verifySignature(message):
    try:
        parts = message.split("_")
        content = parts[0]
        signature = parts[1:]
        #messageSignature = + time + "_" + key_id + "_" + leading + "_" + signature
        sender_key_id = signature[-3]
        sender_key = rings.get_public_key_for_key_id(sender_key_id)
        sender_nums = sender_key.public_numbers()
        
        public_data = rings.get_public_key_ring_data()
        sender_data = []
        for data in public_data:
            if data['key_id'] == sender_key_id:
                sender_data = data

        decrypted_signature = pow(int(signature[-1], 16), sender_nums.e, sender_nums.n)
        digest = hashMessage(content, signature[-4])

        if int(digest, 16) == decrypted_signature:
            return message, sender_data
        else:
            return "Signature cannot be verified!", None
    except (KeyError):
        return "Greska - Potpis ne moze biti verifikovan!", None

def compress(message):
    encodedMessage = message.encode('UTF-8')
    message = zlib.compress(encodedMessage)
    message = message.hex()
    message = ''.join(f"{int(digit, 16):04b}" for digit in message)
    return message

def decompress(message):
    messageHex = hex(int(message, 2))
    messageBytes = bytes.fromhex(messageHex[2:])
    decomppressed = zlib.decompress(messageBytes)
    message = decomppressed.decode('UTF-8')
    return message

#TripleDES logika - pocetak ----------------
def permutationI(size):
    order = []
    for i in range(size):
        order.append(i)
    for i in range(size):
        j = random.randint(0, size-1)
        order[i], order[j] = order[j], order[i]
    return order

def initialPermutation(bits, perm):
    newBits = ""
    for i in range(len(perm)):
        newBits += bits[perm[i]]
    return newBits

def generateKey(size):
    key = ""
    for i in range(size):
        j = random.randint(0, 1)
        key += str(j)
    return key

def keyPermutation(size, reducedSize):
    order = []
    for i in range(size):
        order.append(i)
    for i in range(size):
        j = random.randint(0, size-1)
        order[i], order[j] = order[j], order[i]
    return order[0:reducedSize]

def keyPermutation2(key, order):
    newKey = ""
    for i in range(len(order)):
        newKey += key[order[i]]
    return newKey

def leftShift(key):
    return key[1:] + key[0]

def prepareKeys():
    keys = []
    keys.append(generateKey(64)) # =key[0]
    keyPerm1 = keyPermutation(64, 56)
    keyPerm2 = keyPermutation(56, 48)
    tripleDESKeyParams.append((keys[0], keyPerm1, keyPerm2))
    keys = complete_keys(keys[0], keyPerm1, keyPerm2)

    return keys

def complete_keys(key, keyPerm1, keyPerm2):
    keys = []
    keys.append(key)
    keys[0] = keyPermutation2(keys[0], keyPerm1)

    for i in range(16):
        key = leftShift(keys[i])
        keys.append(key)
    for i in range(16):
        keys[i+1] = keyPermutation2(keys[i+1], keyPerm2)

    return keys

def expansion(size, expandedSize):
    exp = []
    for i in range(expandedSize):
        j = random.randint(0, size - 1)
        exp.append(j)
    return exp

def expansion2(value, order):
    newValue = ""
    for i in range(len(order)):
        newValue += value[order[i]] 
    return newValue

def xorWithKey(value, key):
    value = int(value, 2) ^ int(key, 2)
    value = bin(value)[2:]
    valueStr = ""
    if(len(value) < len(key)):
        for i in range(len(key) - len(value)):
            valueStr += "0"
    valueStr += value
    return valueStr

def generateSBox():
    return [
    [14, 4, 13, 1,  2, 15, 11, 8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7, 4, 14,  2, 13, 1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]]

def applySBox(value, sBox):
    newKey = ""
    i = 0
    while i < len(value):
        row = value[i] + value[i+5]
        col = value[i+1:i+5]
        row = int(row, 2)
        col = int(col, 2)
        newNumber = sBox[row][col]
        newNumberBin = bin(newNumber)[2:]
        if(len(newNumberBin) < 4):
            for j in range(4 - len(newNumberBin)):
                newKey += "0"
        newKey += newNumberBin
        i += 6
    return newKey

def permutation(value, number):
    perm = tripleDESPerms[number]
    newValue = ""
    for i in range(len(perm)):
        newValue += value[perm[i]]
    return newValue

def FeistelRound(value, key, number):
    expand = tripleDESExpands[number]
    value = expansion2(value, expand)
    value = xorWithKey(value, key)
    value = applySBox(value, generateSBox())
    value = permutation(value, number)
    return value

def DESRound(bits, key, number):

    left = bits[0:32]
    right = bits[32:]

    leftNextStr = str(right)
    rightNext = int(left, 2) ^ int(FeistelRound(right, key , number), 2)
    rightNext = bin(rightNext)[2:]
    rightNextStr = ""
    if(len(rightNext) < 32):
        for i in range(32 - len(rightNext)):
            rightNextStr += "0"
    rightNextStr += str(rightNext)

    return leftNextStr, rightNextStr

def inverseIP(bits, perm):
    inversePerm = []
    for i in range(len(perm)):
        inversePerm.append(0)
    for i in range(len(perm)):
        inversePerm[perm[i]] = i

    newBits = ""
    for i in range(len(inversePerm)):
        newBits += bits[inversePerm[i]]
    return newBits

def prepareForDES():
    tripleDESKeys.append(prepareKeys())
    tripleDESKeys.append(prepareKeys())
    tripleDESKeys.append(prepareKeys())
    tripleDESExpands.append(expansion(32, 48))
    tripleDESExpands.append(expansion(32, 48))
    tripleDESExpands.append(expansion(32, 48))
    tripleDESPermsI.append(permutationI(64))
    tripleDESPermsI.append(permutationI(64))
    tripleDESPermsI.append(permutationI(64))
    tripleDESPerms.append(permutationI(32))
    tripleDESPerms.append(permutationI(32))
    tripleDESPerms.append(permutationI(32))

def DES(message, number):
    if len(tripleDESExpands) == 0:
        prepareForDES()

    perm = tripleDESPermsI[number]

    bits = message

    difference = 64 - len(bits) % 64
    if difference < 64:
        for i in range(difference):
            bits = "0" + bits

    keys = tripleDESKeys[number]

    cipher = ""
    allBits = bits
    for k in range(len(allBits) // 64):
        bits = allBits[k*64:(k+1)*64]
        bits = initialPermutation(bits, perm)
        left = ""
        right = ""
        for i in range(16):
            left, right = DESRound(bits, keys[i+1], number)
            bits = left + right
            
        left, right = right, left
        bits = left + right
        bits = inverseIP(bits, perm)
        cipher += bits
    return cipher

def tripleDES(message):
    message = DES(message, 0)
    message = DESDecrypt(message, 1)
    return DES(message, 2)

def tripleDESDecrypt(message):
    message = DESDecrypt(message, 2)
    message = DES(message, 1)
    return DESDecrypt(message, 0)

def DESDecrypt(message, number):
    if len(tripleDESExpands) == 0:
        prepareForDES()

    perm = tripleDESPermsI[number]
    bits = message

    difference = 64 - len(bits) % 64
    if difference < 64:
        for i in range(difference):
            bits = "0" + bits

    keys = tripleDESKeys[number]
    plain = ""
    
    allBits = bits
    for k in range(len(allBits) // 64):
        bits = allBits[k*64:(k+1)*64]
        bits = initialPermutation(bits, perm)
        left = ""
        right = ""
        for i in range(16):
            left, right = DESRound(bits, keys[16-i], number)
            bits = left + right
            
        left, right = right, left
        bits = left + right
        bits = inverseIP(bits, perm)
        plain += bits

    return plain

#TripleDES logika - kraj --------------------

#Cast5 logika - pocetak ---------------------

def CAST_encrypt(message):
    message = message.encode('utf-8')
    with_pad = pad(message, CAST.block_size)
    cipher = CAST.new(cast_key[0], CAST.MODE_CBC, cast_iv[0])
    encrypted = cipher.encrypt(with_pad)
    return base64.b64encode(encrypted).decode('utf-8')

def CAST_decrypt(message):
    ciphertext = base64.b64decode(message.encode('utf-8'))
    decipher = CAST.new(cast_key[0], CAST.MODE_CBC, cast_iv[0])
    decrypted_with_pad = decipher.decrypt(ciphertext)
    without_pad = unpad(decrypted_with_pad, CAST.block_size)
    return without_pad.decode('utf-8')

# Cast5 logika - kraj -----------------------


def convertToRadix(message):
    bytes = message.encode('UTF-8')
    base64Bytes = base64.b64encode(bytes)
    base64Message = base64Bytes.decode('UTF-8')
    return base64Message

def convertFromRadix(message):
    bytes = message.encode('UTF-8')
    messageBytes = base64.b64decode(bytes)
    message = messageBytes.decode('UTF-8')
    return message

def encryptMessage(message, e, n, receiver_key_id, header):
    key_parts = []
    message2 = ""
    
    if "I" in header: #oznacava da se koristi CAST5
        #generisanje kljuca i inicijalne vrednosti za CAST5
        key = generateKey(128)
        cast_key.append(int(key, 2).to_bytes(len(key) // 8, byteorder='big'))
        iv = generateKey(64)
        cast_iv.append(int(iv, 2).to_bytes(len(iv) // 8, byteorder='big'))
        message2 = CAST_encrypt(message)

        #cuvanje parametara za CAST5
        key_parts.append(cast_key[0])
        key_parts.append(cast_iv[0])
    else:
        if "C" not in header: #compression - neophodna za tripleDES
            message = compress(message)

        message2 = tripleDES(message)

        #cuvanje parametara za tripleDES
        for i in range(len(tripleDESKeyParams)):
            key_parts.append(tripleDESKeyParams[i])
        for i in range(len(tripleDESExpands)):
            key_parts.append(tripleDESExpands[i])
        for i in range(len(tripleDESPerms)):
            key_parts.append(tripleDESPerms[i])
        for i in range(len(tripleDESPermsI)):
            key_parts.append(tripleDESPermsI[i])

    encryptedSessionKeys = encrypt_parts(e, n, str(key_parts))
    almostFinalMessage = str(message2) + "_" + encryptedSessionKeys + "_" + receiver_key_id
    return almostFinalMessage

def encrypt_parts(e, n, keys):
    total = ""
    #zbog prevelike poruke, deli se u chunk-ove od po 32 karaktera
    chunk_size = 32

    for i in range(0, len(keys), chunk_size):
        chunk = keys[i:i+chunk_size]
        message_bytes = chunk.encode('utf-8')
        message_int = int.from_bytes(message_bytes, byteorder='big')
        encrypted_int = pow(message_int, e, n)
        encrypted_hex = hex(encrypted_int)[2:]
        total += encrypted_hex + ";"

    return total

def decrypt_parts(encrypted_parts, d, n, header):
    decrypted_message = []
    parts = encrypted_parts.split(";")
    for encrypted_part in parts:
        if encrypted_part == "":
            break
        encrypted_int = int(encrypted_part, 16)
        decrypted_int = pow(encrypted_int, d, n)
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
        decrypted_message.append(decrypted_bytes.decode('utf-8'))

    decrypted_message =  ''.join(decrypted_message)
    key_parts = eval(decrypted_message)

    if "I" not in header: #Ako je koricen TripleDES:
        tripleDESKeys.clear()
        tripleDESExpands.clear()
        tripleDESPerms.clear()
        tripleDESPermsI.clear()

        tripleDESKeys.append(complete_keys(key_parts[0][0], key_parts[0][1], key_parts[0][2]))
        tripleDESKeys.append(complete_keys(key_parts[1][0], key_parts[1][1], key_parts[1][2]))
        tripleDESKeys.append(complete_keys(key_parts[2][0], key_parts[2][1], key_parts[2][2]))

        tripleDESExpands.append(key_parts[3])
        tripleDESExpands.append(key_parts[4])
        tripleDESExpands.append(key_parts[5])

        tripleDESPerms.append(key_parts[6])
        tripleDESPerms.append(key_parts[7])
        tripleDESPerms.append(key_parts[8])

        tripleDESPermsI.append(key_parts[9])
        tripleDESPermsI.append(key_parts[10])
        tripleDESPermsI.append(key_parts[11])
    else: #Ako je koriscen Cast5:
        cast_key.clear()
        cast_iv.clear()
        cast_key.append(key_parts[0])
        cast_iv.append(key_parts[1])

def decryptMessage(message, password, header):
    m2 = message.rsplit('_', 2)
    m3 = m2[0] # encrypted signature + message
    m4 = m2[1] # encrypted session keys
    key_id = m2[2]

    try:
        public_key = rings.get_public_key_for_key_id(key_id)
        private_key = rings.get_private_key_for_key_id(key_id, password)
        public_nums = public_key.public_numbers()
        private_nums = private_key.private_numbers()

        decrypt_parts(m4, private_nums.d, public_nums.n, header)
        
        if "I" not in header:
            m5 = tripleDESDecrypt(m3)
            if "C" not in header: #ona od ranije neophodna kompresija za tripleDES
                m5 = decompress(m5)
        else:
            m5 = CAST_decrypt(m3)

        return m5

    except (TypeError, ValueError):
        return "Greska - pogresna lozinka za dekripciju!"
    except (KeyError, AttributeError):
        return "Greska - pogresan kljuc!"
#!/usr/bin/env python3
import random, base64, binascii, argparse
import numpy as np

def pad_hex(num, n):
    tmp = format(num, 'x')
    while len(tmp) != n:
        tmp = '0' + tmp
    return tmp

def pad_matrix(text):
    tmp = [ord(x) for x in text]
    # pad 
    while len(tmp) % 9 != 0:
        tmp.append(0)
    return tmp

def generate_matix():
    success = False
    identity = np.array([[1, 0, 0], [0, 1, 0], [0, 0, 1]])
    while success == False:
        matrix = [random.randint(1, 80) for i in range(9)]
        matrix = np.array(matrix).reshape(3, 3)
        try:
            inverse = np.linalg.inv(matrix)
        except np.linalg.LinAlgError:
            # Not invertible. Skip this one.
            pass
        else:
            passed = 0
            if np.array_equal(identity, np.dot(matrix, inverse)):
                for i in inverse:
                    for j in i:
                        string = str(j)
                        string = string.split('.')
                        if len(string[1]) <= 10:
                            passed += 1
                if passed == 9:
                    success = True
    return matrix

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def xor(x, y):
    tmp = []
    for i in range(len(x)):
        tmp.append(x[i] ^ y[i])
    return tmp

def modblock(x):
    tmp = []
    for i in x:
        tmp.append(i % 256)
    return tmp

def generate_key(max):
    tmp = []
    for i in range(9):
        tmp.append(random.randint(0, max))
    return tmp

def cipher_block(prevblock_mod, block, xor_key, encryption_matrix, shuffle_key, blockNo, debug):
    if debug == True:
        print('Current block: {}'.format(block))
    tmp = xor(prevblock_mod, block)
    if debug == True:
        print('After xor with prev block/iv\n{}'.format(tmp))
    tmp = np.array(tmp).reshape(3, 3)
    shuffle_block(tmp, shuffle_key, blockNo)
    if debug == True:
        print('After shuffling\n{}'.format(tmp))
    tmp = np.dot(tmp, encryption_matrix)
    if debug == True:
        print('After Multiplication\n{}'.format(tmp))
    tmp = flatten_matrix(tmp)
    tmp = xor(tmp, xor_key)
    if debug == True:
        print('After xor with key\n{}'.format(tmp))
    return tmp

def uncipher_block(prevblock_mod, block, xor_key, decryption_matrix, shuffle_key, blockNo, debug):
    tmp = xor(block, xor_key)
    if debug == True:
        print('After xor with key\n{}'.format(tmp))
    tmp = np.array(tmp).reshape(3, 3).astype(int)
    tmp = np.dot(tmp, decryption_matrix)
    if debug == True:
        print('After Multiplication\n{}'.format(tmp))
    unshuffle_block(tmp, shuffle_key, blockNo)
    if debug == True:
        print('After Unshuffling\n{}'.format(tmp))
    tmp = [int(x) for x in flatten_matrix(tmp)]
    tmp = xor(tmp, prevblock_mod)
    if debug == True:
        print('After xor with prev block/iv\n{}'.format(tmp))
    return tmp

def flatten_matrix(matrix):
    tmp = []
    for i in matrix:
        tmp.extend(i.flatten())
    return tmp

def shuffle_block(matrix, shuffle_key, blockNo):
    for i in range(blockNo, blockNo+208, 8):
        if i > 204:
            i = i % 205
        first = [int(shuffle_key[i:i+2], 2)-1, int(shuffle_key[i+2:i+4], 2)-1]
        second = [int(shuffle_key[i+4:i+6], 2)-1, int(shuffle_key[i+6:i+8], 2)-1]
        if -1 in first or -1 in second:
            continue
        swap(matrix, first, second)

def unshuffle_block(matrix, shuffle_key, blockNo):
    shuffles = []
    for i in range(blockNo, blockNo+208, 8):
        if i > 204:
            i = i % 205
        first = [int(shuffle_key[i:i+2], 2)-1, int(shuffle_key[i+2:i+4], 2)-1]
        second = [int(shuffle_key[i+4:i+6], 2)-1, int(shuffle_key[i+6:i+8], 2)-1]
        if -1 in first or -1 in second:
            continue
        shuffles.append([first, second])
    shuffles.reverse()
    for i in shuffles:
        swap(matrix, i[0], i[1])

def swap(matrix, first, second):
    tmp = matrix[first[0]][first[1]]
    matrix[first[0]][first[1]] = matrix[second[0]][second[1]]
    matrix[second[0]][second[1]] = tmp

def encryption(plaintext, debug=False):
    msg = pad_matrix(plaintext)
    msg = list(chunks(msg, 9))
    iv = generate_key(255)
    xor_key = generate_key(65535)
    encryption_matrix = generate_matix()
    key = ''.join([pad_hex(x, 4) for x in xor_key]) + ''.join([pad_hex(x, 2) for x in flatten_matrix(encryption_matrix)])
    shuffle_key = str(bin(int(key, 16)))[2:]
    if debug == True:
        print('First Block\nIV: {}'.format(iv))
    cipher = cipher_block(iv, msg[0], xor_key, encryption_matrix, shuffle_key, 0, debug)
    prevcipher = cipher
    ciphertext = cipher
    for i in range(1, len(msg)):
        if debug == True:
            print('\n{} block'.format(i+1))
        cipher = cipher_block(modblock(prevcipher), msg[i], xor_key, encryption_matrix, shuffle_key, i, debug)
        prevcipher = cipher
        ciphertext.extend(cipher)
    if debug == True:
        print('Ciphertext: {}'.format(iv + ciphertext))
    ciphertext = ''.join([pad_hex(x, 2) for x in iv]) + ''.join([pad_hex(x, 4) for x in ciphertext])
    if debug == True:
        print('\nCiphertext hex: {}'.format(ciphertext))
    base85 = str(base64.b85encode(bytes.fromhex(ciphertext)))[2:-1]
    print("\nCiphertext b85: " + base85)
    print('Key: {}'.format(key))

def decryption(ciphertext, key, debug=False):
    cipher = binascii.hexlify(base64.b85decode(ciphertext))
    if debug == True:
        print('Ciphertext hex: {}'.format(cipher))
    iv = [int(cipher[i:i+2], 16) for i in range(0, 18, 2)]
    cipher = [int(cipher[i:i+4], 16) for i in range(18, len(cipher), 4)]
    xor_key = [int(key[i:i+4], 16) for i in range(0, 36, 4)]
    shuffle_key = str(bin(int(key, 16)))[2:]
    encryption_matrix = [int(key[i:i+2], 16) for i in range(36, 54, 2)]
    encryption_matrix = np.array(encryption_matrix).reshape(3, 3).astype(int)
    if debug == True:
        print('\nXOR key: {}\n\nEncryption Matrix\n{}'.format(xor_key, encryption_matrix))
    decryption_matrix = np.linalg.inv(encryption_matrix)
    if debug == True:
        print('\nDecryption matrix\n{}'.format(decryption_matrix))
        print('\nIV: {}'.format(iv))
        print('\nCiphertext: {}'.format(cipher))
    cipher = list(chunks(cipher, 9))
    asciiCodes = []
    tmp = []
    for i in range(len(cipher)-1, 0, -1):
        if debug == True:
            print('\n{} block'.format(i+1))
        tmp = uncipher_block(modblock(cipher[i-1]), cipher[i], xor_key, decryption_matrix, shuffle_key, i, debug)
        asciiCodes.append(tmp)
    asciiCodes.append( uncipher_block(iv, cipher[0], xor_key, decryption_matrix, shuffle_key, 0, debug))
    asciiCodes.reverse()
    plaintext = ''
    for block in asciiCodes:
        for char in block:
            if char == 0:
                break
            else:
                plaintext += chr(char)
    if debug == True:
        print('\nAscii codes\n{}'.format(asciiCodes))
    print('\nPlaintext\n{}'.format(plaintext))

if __name__== "__main__":
    # https://stackoverflow.com/a/31347222
    parser = argparse.ArgumentParser(description='Spinning Zebra Encryption')
    ed_group = parser.add_mutually_exclusive_group(required=True)
    ed_group.add_argument('-e','--encrypt', help='Encrypt text', dest='operation', action='store_true')
    ed_group.add_argument('-d','--decrypt', help='Decrypt text', dest='operation', action='store_false')
    parser.add_argument('-v','--verbose', dest='verbose', action='store_true')
    parser.set_defaults(verbose=False, operation=True)
    args = vars(parser.parse_args())
    if args['operation']:
        encryption(input("Plaintext: "), debug=args['verbose'])
    else:
        ciphertext = input("Ciphertext Base85: ")
        key = input('Key: ')
        decryption(ciphertext, key, debug=args['verbose'])
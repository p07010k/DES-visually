from sys import argv
from random import randint
from bitstring import BitString

from destables import IP, invIP, E, P, S, PC1, PC2


def splitToN(x, n):
    """
    Splits a bitstring x into n pieces of equal len
    Returns a tuple of n pieces
    """
    l = x.len
    return tuple(x[(l*i//n):(l*(i+1)//n)] for i in range(n))


def permute(x, perm_table):
    y = BitString()
    for n in perm_table:
        y += x[n-1:n]
    return y


def substitute(x, subs_table):
    row = (x[0:1] + x[5:6]).uint
    col = x[1:5].uint
    return BitString(uint=subs_table[row][col], length=4)


def fFunction(k, R):
    R_expanded = permute(R, E)
    R_xor_k = R_expanded ^ k
    pieces6b = list(splitToN(R_xor_k, 8))
    pieces4b = map(substitute, pieces6b, S)
    R_after_S = BitString('').join(pieces4b)
    return permute(R_after_S, P)


def round(L, R, k):
    L, R = R, (L ^ fFunction(k, R))
    return L, R


def keyGen():
    """Generates a random 64-bit key as BitString"""
    return BitString(uint=randint(0, 2**64), length=64)


def transform(C, D, i, enc):
    """
    @param x BitString: input bitstring
    @param i int: The # of a Round
    @param enc bool: True if encrypt, False if decrypt
    
    @return k_i, C, D output round key & the C, D halves for next round input
    """
    if enc:
        if i in {1, 2, 9, 16}:
            s = 1
        else: 
            s = 2
        # rol() -- Rotate bits to the left.
        C.rol(s)
        D.rol(s)
    else:
        if i == 16:
            s = 0
        elif i in {1, 8, 15}: 
            s = 1
        else:
            s = 2
        # ror() -- Rotate bits to the right.
        C.ror(s)
        D.ror(s)
    k_i = permute(C + D, PC2)
    return k_i, C, D


# x sample: BitString(bytes=b'engineer')
def des(x, k, enc=True):
    """
    des function
    
    @param x BitString length=64: input 
        (Plaintext if enc==True else Ciphertext)
    @param k BitString length=64: 64-bit Key
    @param enc bool: True if encrypt mode; False if decrypt mode
    
    @return y BitString
    """
    # initial permutation of 64-bit input
    IPx = permute(x, IP)
    # spliting it into left and right 32-bit halves
    L, R = splitToN(IPx, 2)
    
    # converting 64-bit key to 56-bit key
    PC1k = permute(k, PC1)
    # spliting 56-bit key into 28-bit halves
    C, D = splitToN(PC1k, 2)
    
    rounds = range(1, 17) if enc else reversed(range(1, 17))
    
    for i in rounds:
        k_i, C, D = transform(C, D, i, enc)
        L, R = round(L, R, k_i)
    
    IPy = R + L
    # applying IP deg -1
    y = permute(IPy, invIP)
    return y

if __name__ == '__main__':
    if len(argv) < 2:
        print('input: des.py [encrypt|decrypt]')
        exit()
    else:
        if argv[1][0] in {'e', 'E'}:  # arg starts with 'e' means ENCRYPT
            enc = True
        elif argv[1][0] in {'d', 'D'}:  # arg starts with 'd' means DECRYPT
            enc = False
        else:
            print('input: des.py [encrypt|decrypt]')
            exit()
    
    if enc:
        plaintext = input('8-character plaintext: ').encode()
        x = BitString(bytes=plaintext)
    else:
        ciphertext = input('hex ciphertext: ')
        x = BitString('0x'+ciphertext)
    
    key = input('HEX key [enter = generate]: ')
    if key == '':
        k = keyGen()
    else:
        k = BitString(uint=int(key, 16), length=64)
    print('Key used: {}'.format(k.hex))
    
    print('Encrypting...' if enc else 'Decrypting...')
    y = des(x, k, enc)
    
    if enc:
        print('Ciphertext: {}'.format(y.hex))
    else:
        print('Plaintext: {}'.format(y.bytes.decode()))

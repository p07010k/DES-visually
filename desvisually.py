from sys import exit
from copy import deepcopy
from random import randint
from datetime import datetime
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


def keyGen():
    """Generates a random 64-bit key as BitString"""
    return BitString(uint=randint(0, 2**64), length=64)


if __name__ == '__main__':
    plaintext = input('8-character plaintext: ')
    x = BitString(bytes=plaintext.encode())
        
    key = input('HEX key [enter = generate]: ')
    if key == '':
        k = keyGen()
    else:
        k = BitString(uint=int(key, 16), length=64)
    
    if x.len != 64 or k.len != 64:
        exit('Plaintext and key must be 64-bit long!')
    
    # 1 Initial permutation
    IPx = permute(x, IP)
    L_0, R_0 = splitToN(IPx, 2)
    
    # 2 Permuted choice 1
    PC1k = permute(k, PC1)
    C_0, D_0 = splitToN(PC1k, 2)
    
    # 3 Transform 1
    C_1, D_1 = deepcopy(C_0), deepcopy(D_0)
    C_1.rol(1)
    D_1.rol(1)
    CD = C_1 + D_1
    
    # 4 Permuted choice 2
    k_1 = permute(CD, PC2)
    
    # 5.1 E expansion
    R_expanded = permute(R_0, E)
    
    # 5.2 E(R_0) xor k_1
    R_xor_k = R_expanded ^ k_1
    pieces6b = list(splitToN(R_xor_k, 8))
    
    # 5.3 S-boxes
    p = pieces6b[0]
    row_bin = (p[0:1] + p[5:6]).bin
    row = (p[0:1] + p[5:6]).uint
    col_bin = p[1:5].bin
    col = p[1:5].uint
    sub_chosen = S[0][row][col]
    sub_chosen_bin = bin(sub_chosen)[2:]
    pieces4b = list(map(substitute, pieces6b, S))
    R_after_S = BitString('').join(pieces4b)
    
    # 5.4 P permutation
    f_out = permute(R_after_S, P)
    
    # 6 L_0 xor f-function output
    R_1 = L_0 ^ f_out
    
    # Creating a report file
    now = datetime.now()
    filename = 'des{}.txt'.format(now.strftime('%Y%m%d_%H%M%S'))
    with open(filename, 'w', encoding='utf-8') as f:
        
        f.write('DES Encryption detailed report\n')
        f.write('{}\n'.format(now))
        f.write('\n')
        f.write('Plaintext (x): {}\n'.format(plaintext))
        f.write('hex (ASCII):\n')
        f.write('{}\n'.format(x.hex))
        f.write('bin:\n')
        f.write('{}\n'.format(x.bin))
        f.write('\n')
        f.write('64-bit key\n')
        f.write('hex:\n')
        f.write('{}\n'.format(k.hex))
        f.write('bin:\n')
        f.write('{}\n'.format(k.bin))
        f.write('\n')
        f.write('Overview of Round 1:\n')
        f.write('                                                     k\n')
        f.write('                                              {}\n'.format(k.hex))
        f.write('                                                     ↓\n')
        f.write('           x                                       [PC-1]\n')
        f.write('    {}                                 ↓\n'.format(x.hex))
        f.write('           ↓                                   {}\n'.format(PC1k.hex))
        f.write('          [IP]                                   ↓        ↓\n')
        f.write('           ↓                                    C_0      D_0\n')
        f.write('    {}                          {}  {}\n'.format(IPx.hex, C_0.hex, D_0.hex))
        f.write('       ↓        ↓                                ↓        ↓\n')
        f.write('      L_0      R_0                             [LS1]    [LS1]\n')
        f.write('   {}  {}                            ↓        ↓\n'.format(L_0.hex, R_0.hex))
        f.write('       ↓        ↓         k_1                   C_1      D_1\n')
        f.write('       ↓       [f] ←  {} ← [PC-2] ← {}  {}\n'.format(k_1.hex, C_1.hex, D_1.hex))
        f.write('       ↓        ↓                                ↓        ↓\n')
        f.write('     (XOR) ← {}                            …        …\n'.format(f_out.hex))
        f.write('       ↓\n')
        f.write('       ⤷→→→→→→→→⤵\n')    
        f.write('                ↓\n')
        f.write('  L_1 = R_0    R_1\n')
        f.write('   {}  {}\n'.format(R_0.hex, R_1.hex))
        f.write('       ↓        ↓\n')
        f.write('       …        …\n')
        f.write('\n')
        f.write('\n')
        f.write('1. Initial Permutation IP(x)\n')
        f.write('  The output value is splited into the halves: L_0, R_0\n')
        f.write('\n')
        f.write('  x = {}    →  IP(x) = {}\n'.format(x.hex, IPx.hex))
        
        for j in range(8):
            f.write('  ')
            for i in range(8):
                f.write('{:0>2} '.format(j*8+i+1))
            f.write('    ')
            for i in range(8):
                f.write('{:0>2} '.format(IP[j*8+i]))
            f.write('\n  ')
            for i in range(8):
                f.write('{:>2} '.format(x[j*8+i:j*8+i+1].bin))
            f.write('    ')
            for i in range(8):
                f.write('{:>2} '.format(IPx[j*8+i:j*8+i+1].bin))
            f.write('\n')
            f.write('\n')
        
        f.write('  IP(x)\n')
        f.write('  bin:\n')
        f.write('  {}\n'.format(IPx.bin))
        f.write('  hex:\n')
        f.write('  {}\n'.format(IPx.hex))
        f.write('\n')
        f.write('  L_0                              R_0\n')
        f.write('  bin:                             bin:\n')
        f.write('  {} {}\n'.format(L_0.bin, R_0.bin))
        f.write('  hex:                             hex:\n')
        f.write('  {}                         {}\n'.format(L_0.hex, R_0.hex))
        f.write('\n')
        f.write('\n')
        f.write('2. Permuted choice 1 PC-1(k)\n')
        f.write('  Permutes 64-bit key into 56-bit key\n')
        f.write('\n')
        f.write('  k = {}    →   PC-1(k) = {}\n'.format(k.hex, PC1k.hex))
        
        for j in range(8):
            f.write('  ')
            for i in range(8):
                f.write('{:0>2} '.format(j*8+i+1))
            f.write('    ')
            if j < 7:
                for i in range(8):
                    f.write('{:0>2} '.format(PC1[j*8+i]))
            f.write('\n  ')
            for i in range(8):
                f.write('{:>2} '.format(k[j*8+i:j*8+i+1].bin))
            f.write('    ')
            if j < 7:
                for i in range(8):
                    f.write('{:>2} '.format(PC1k[j*8+i:j*8+i+1].bin))
            f.write('\n')
            f.write('\n')
        
        f.write('  PC-1(k)\n')
        f.write('  bin:\n')
        f.write('  {}\n'.format(PC1k.bin))
        f.write('  hex:\n')
        f.write('  {}\n'.format(PC1k.hex))
        f.write('\n')
        f.write('  C_0                          D_0\n')
        f.write('  bin:                         bin:\n')
        f.write('  {} {}\n'.format(C_0.bin, D_0.bin))
        f.write('  hex:                         hex:\n')
        f.write('  {}                      {}\n'.format(C_0.hex, D_0.hex))
        f.write('\n')
        f.write('\n')
        f.write('3. Transformation 1\n')
        f.write('  Round #1 => the two halves are rotated left by 1 bit\n')
        f.write('\n')
        f.write('              C_i                             D_i\n')
        f.write('i=0  {}    {}\n'.format(C_0.bin, D_0.bin))
        f.write('i=1   {}    {}\n'.format(C_1.bin, D_1.bin))
        f.write('\n')
        f.write('  C_1 hex: {}\n'.format(C_1.hex))
        f.write('  D_1 hex: {}\n'.format(D_1.hex))
        f.write('  PC-2 input: {}\n'.format(CD.hex))
        f.write('\n')
        f.write('  C_1 and D_1 are used in transformation 2\n')
        f.write('\n')
        f.write('\n')
        f.write('4. Permuted Choice 2 PC-2\n')
        f.write('  Outputs 48-bit round key k_1\n')
        f.write('\n')
        f.write('  C_1|D_1 = {}  → PC-2(C_1|D_1) = {}\n'.format(CD.hex, k_1.hex))
        
        for j in range(7):
            f.write('  ')
            for i in range(8):
                f.write('{:0>2} '.format(j*8+i+1))
            f.write('    ')
            if j < 6:
                for i in range(8):
                    f.write('{:0>2} '.format(PC2[j*8+i]))
            f.write('\n  ')
            for i in range(8):
                f.write('{:>2} '.format(CD[j*8+i:j*8+i+1].bin))
            f.write('    ')
            if j < 6:
                for i in range(8):
                    f.write('{:>2} '.format(k_1[j*8+i:j*8+i+1].bin))
            f.write('\n')
            f.write('\n')
        
        f.write('  k_1\n')
        f.write('  bin:\n')
        f.write('  {}\n'.format(k_1.bin))
        f.write('  hex:\n')
        f.write('  {}\n'.format(k_1.hex))
        f.write('\n')
        f.write('\n')
        f.write('5. f-function\n')
        f.write('\n')
        f.write('  5.1 R_0 Expansion\n')
        f.write('\n')
        f.write('    R_0         →  E(R_0)\n')
        
        for j in range(8):
            f.write('  ')
            for i in range(4):
                f.write('{:0>2} '.format(j*4+i+1))
            f.write('    ')
            for i in range(6):
                f.write('{:0>2} '.format(E[j*6+i]))
            f.write('\n  ')
            for i in range(4):
                f.write('{:>2} '.format(R_0[j*4+i:j*4+i+1].bin))
            f.write('    ')
            for i in range(6):
                f.write('{:>2} '.format(R_expanded[j*6+i:j*6+i+1].bin))
            f.write('\n')
            f.write('\n')
        
        f.write('\n')
        f.write('  5.2 E(R_0) xor k_1\n')
        f.write('    Then XORed value is splited into 8 6-bit pieces\n')
        f.write('\n')
        f.write('    E(R_0)  {}\n'.format(R_expanded.bin))
        f.write('       k_1  {}\n'.format(k_1.bin))
        f.write('       xor  {}\n'.format(R_xor_k.bin))
        f.write('    pieces:\n')
        f.write('        {}\n'.format(' '.join([x.bin for x in pieces6b])))
        f.write('\n')
        f.write('\n')
        f.write('  5.3 S-boxes\n')
        f.write('    Example on S-box S_1. Other S-boxes applied similarly\n')
        f.write('\n')
        f.write('                                piece #1: {}\n'.format(p.bin))
        f.write('    left-most bit | right-most bit (row): {}\n'.format(row_bin))
        f.write('                    middle bits (column): {}\n'.format(col_bin))
        f.write('    S_1:\n')
        f.write('       0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111\n')
        f.write('    00  14    4   13    1    2   15   11    8    3   10    6   12    5    9    0    7\n')
        f.write('    01   0   15    7    4   14    2   13    1   10    6   12   11    9    5    3    8\n')
        f.write('    10   4    1   14    8   13    6    2   11   15   12    9    7    3   10    5    0\n')
        f.write('    11  15   12    8    2    4    9    1    7    5   11    3   14   10    0    6   13\n')
        f.write('\n')
        f.write('    Substitution chosen: {}\n'.format(sub_chosen))
        f.write('    bin: {}\n'.format(sub_chosen_bin))
        f.write('\n')
        f.write('    All substitutions:\n')
        f.write('    {}\n'.format(' '.join([x.bin for x in pieces4b])))
        f.write('\n')
        f.write('    S-boxes Output\n')
        f.write('    bin:\n')
        f.write('    {}\n'.format(R_after_S.bin))
        f.write('    hex:\n')
        f.write('    {}\n'.format(R_after_S.hex))
        f.write('\n')
        f.write('\n')
        f.write('  5.4 Permutation P\n')
        f.write('    This P-box output is f-function output\n')
        f.write('\n')
        f.write('    S-boxes output          →  f output = {}\n'.format(f_out.hex))
        
        for j in range(4):
            f.write('  ')
            for i in range(8):
                f.write('{:0>2} '.format(j*8+i+1))
            f.write('    ')
            for i in range(8):
                f.write('{:0>2} '.format(P[j*8+i]))
            f.write('\n  ')
            for i in range(8):
                f.write('{:>2} '.format(R_after_S[j*8+i:j*8+i+1].bin))
            f.write('    ')
            for i in range(8):
                f.write('{:>2} '.format(f_out[j*8+i:j*8+i+1].bin))
            f.write('\n')
            f.write('\n')
        
        f.write('\n')
        f.write('    f-function output\n')
        f.write('    bin:\n')
        f.write('    {}\n'.format(f_out.bin))
        f.write('    hex:\n')
        f.write('    {}\n'.format(f_out.hex))
        f.write('\n')
        f.write('\n')
        f.write('6. L_0 xor f-function output\n')
        f.write('  XORed value is R_1\n')
        f.write('\n')
        f.write('  L_0 = {}\n'.format(L_0.hex))
        f.write('\n')
        f.write('       L_0  {}\n'.format(L_0.bin))
        f.write('  f output  {}\n'.format(f_out.bin))
        f.write('       xor  {}\n'.format(R_1.bin))
        f.write('\n')
        f.write('  R_1 = {}\n'.format(R_1.hex))
        
        print('Done. Check {}'.format(filename))

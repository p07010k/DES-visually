# DES visually
This tool runs the first round of DES and creates a text report, revealing all intermediate values. It is useful for studying DES encryption algorithm.

The tool is made for learning purposes only, as it encrypths only an 8-byte block and is not suitable for actual encryption function.

Made by p07010k in March 2020.

## Requirements
`bitstring` module is needed. Install from pip:
```
pip install bitstring
```

## Usage
There are two options:
1. Run all 16 rounds of DES with des.py script, and get cyphertext in hex. 
2. Run only the 1<sup>st</sup> round with desvisually.py, and get a text report, revealing all intermediate values and their transformations.

### 1. des.py
Usage:
```
des.py [encrypt|decrypt]
```
**Example:** We have an 8-byte string `November`, and would like to encrypt it. The script will invite us to paste the plaintext and a 8-byte key in hex. It is possible to generate a random key by entering empty string:
```
>des.py encrypt
8-character plaintext: November
HEX key [enter = generate]:
Key used: b742c7238bcca586
Encrypting...
Ciphertext: 67a7d19f8cbb875c
```
Now we have the 8-byte string encrypted with DES. Copy the key and the ciphertext. Then run `des.py` in decrypt mode and paste them: 
```
>des.py decrypt
hex ciphertext: 67a7d19f8cbb875c
HEX key [enter = generate]: b742c7238bcca586
Key used: b742c7238bcca586
Decrypting...
Plaintext: November
```
We have decrypted the initial string.

### 2. desvisually.py
The `desvisually.py` script has no arguments.

Usage of the script is kind of similar to the previous. Let's run it with the same plaintext:
```
>desvisually.py
8-character plaintext: November
HEX key [enter = generate]:
Done. Check des20210408_021014.txt
```

**The example of a text report:**
```
DES Encryption detailed report
2021-04-08 02:10:14.648895

Plaintext (x): November
hex (ASCII):
4e6f76656d626572
bin:
0100111001101111011101100110010101101101011000100110010101110010

64-bit key
hex:
755b210afeb8484b
bin:
0111010101011011001000010000101011111110101110000100100001001011

Overview of Round 1:
                                                     k
                                              755b210afeb8484b
                                                     ???
           x                                       [PC-1]
    4e6f76656d626572                                 ???
           ???                                   30d33539a11fa3
          [IP]                                   ???        ???
           ???                                    C_0      D_0
    ff845f5a00fe13a7                          30d3353  9a11fa3
       ???        ???                                ???        ???
      L_0      R_0                             [LS1]    [LS1]
   ff845f5a  00fe13a7                            ???        ???
       ???        ???         k_1                   C_1      D_1
       ???       [f] ???  a2acc92c5ba9 ??? [PC-2] ??? 61a66a6  3423f47
       ???        ???                                ???        ???
     (XOR) ??? d42e5e3d                            ???        ???
       ???
       ??????????????????????????????
                ???
  L_1 = R_0    R_1
   00fe13a7  2baa0167
       ???        ???
       ???        ???


1. Initial Permutation IP(x)
  The output value is splited into the halves: L_0, R_0

  x = 4e6f76656d626572    ???  IP(x) = ff845f5a00fe13a7
  01 02 03 04 05 06 07 08     58 50 42 34 26 18 10 02 
   0  1  0  0  1  1  1  0      1  1  1  1  1  1  1  1 

  09 10 11 12 13 14 15 16     60 52 44 36 28 20 12 04 
   0  1  1  0  1  1  1  1      1  0  0  0  0  1  0  0 

  17 18 19 20 21 22 23 24     62 54 46 38 30 22 14 06 
   0  1  1  1  0  1  1  0      0  1  0  1  1  1  1  1 

  25 26 27 28 29 30 31 32     64 56 48 40 32 24 16 08 
   0  1  1  0  0  1  0  1      0  1  0  1  1  0  1  0 

  33 34 35 36 37 38 39 40     57 49 41 33 25 17 09 01 
   0  1  1  0  1  1  0  1      0  0  0  0  0  0  0  0 

  41 42 43 44 45 46 47 48     59 51 43 35 27 19 11 03 
   0  1  1  0  0  0  1  0      1  1  1  1  1  1  1  0 

  49 50 51 52 53 54 55 56     61 53 45 37 29 21 13 05 
   0  1  1  0  0  1  0  1      0  0  0  1  0  0  1  1 

  57 58 59 60 61 62 63 64     63 55 47 39 31 23 15 07 
   0  1  1  1  0  0  1  0      1  0  1  0  0  1  1  1 

  IP(x)
  bin:
  1111111110000100010111110101101000000000111111100001001110100111
  hex:
  ff845f5a00fe13a7

  L_0                              R_0
  bin:                             bin:
  11111111100001000101111101011010 00000000111111100001001110100111
  hex:                             hex:
  ff845f5a                         00fe13a7


2. Permuted choice 1 PC-1(k)
  Permutes 64-bit key into 56-bit key

  k = 755b210afeb8484b    ???   PC-1(k) = 30d33539a11fa3
  01 02 03 04 05 06 07 08     57 49 41 33 25 17 09 01 
   0  1  1  1  0  1  0  1      0  0  1  1  0  0  0  0 

  09 10 11 12 13 14 15 16     58 50 42 34 26 18 10 02 
   0  1  0  1  1  0  1  1      1  1  0  1  0  0  1  1 

  17 18 19 20 21 22 23 24     59 51 43 35 27 19 11 03 
   0  0  1  0  0  0  0  1      0  0  1  1  0  1  0  1 

  25 26 27 28 29 30 31 32     60 52 44 36 63 55 47 39 
   0  0  0  0  1  0  1  0      0  0  1  1  1  0  0  1 

  33 34 35 36 37 38 39 40     31 23 15 07 62 54 46 38 
   1  1  1  1  1  1  1  0      1  0  1  0  0  0  0  1 

  41 42 43 44 45 46 47 48     30 22 14 06 61 53 45 37 
   1  0  1  1  1  0  0  0      0  0  0  1  1  1  1  1 

  49 50 51 52 53 54 55 56     29 21 13 05 28 20 12 04 
   0  1  0  0  1  0  0  0      1  0  1  0  0  0  1  1 

  57 58 59 60 61 62 63 64     
   0  1  0  0  1  0  1  1     

  PC-1(k)
  bin:
  00110000110100110011010100111001101000010001111110100011
  hex:
  30d33539a11fa3

  C_0                          D_0
  bin:                         bin:
  0011000011010011001101010011 1001101000010001111110100011
  hex:                         hex:
  30d3353                      9a11fa3


3. Transformation 1
  Round #1 => the two halves are rotated left by 1 bit

              C_i                             D_i
i=0  0011000011010011001101010011    1001101000010001111110100011
i=1   0110000110100110011010100110    0011010000100011111101000111

  C_1 hex: 61a66a6
  D_1 hex: 3423f47
  PC-2 input: 61a66a63423f47

  C_1 and D_1 are used in transformation 2


4. Permuted Choice 2 PC-2
  Outputs 48-bit round key k_1

  C_1|D_1 = 61a66a63423f47  ??? PC-2(C_1|D_1) = a2acc92c5ba9
  01 02 03 04 05 06 07 08     14 17 11 24 01 05 03 28 
   0  1  1  0  0  0  0  1      1  0  1  0  0  0  1  0 

  09 10 11 12 13 14 15 16     15 06 21 10 23 19 12 04 
   1  0  1  0  0  1  1  0      1  0  1  0  1  1  0  0 

  17 18 19 20 21 22 23 24     26 08 16 07 27 20 13 02 
   0  1  1  0  1  0  1  0      1  1  0  0  1  0  0  1 

  25 26 27 28 29 30 31 32     41 52 31 37 47 55 30 40 
   0  1  1  0  0  0  1  1      0  0  1  0  1  1  0  0 

  33 34 35 36 37 38 39 40     51 45 33 48 44 49 39 56 
   0  1  0  0  0  0  1  0      0  1  0  1  1  0  1  1 

  41 42 43 44 45 46 47 48     34 53 46 42 50 36 29 32 
   0  0  1  1  1  1  1  1      1  0  1  0  1  0  0  1 

  49 50 51 52 53 54 55 56     
   0  1  0  0  0  1  1  1     

  k_1
  bin:
  101000101010110011001001001011000101101110101001
  hex:
  a2acc92c5ba9


5. f-function

  5.1 R_0 Expansion

    R_0         ???  E(R_0)
  01 02 03 04     32 01 02 03 04 05 
   0  0  0  0      1  0  0  0  0  0 

  05 06 07 08     04 05 06 07 08 09 
   0  0  0  0      0  0  0  0  0  1 

  09 10 11 12     08 09 10 11 12 13 
   1  1  1  1      0  1  1  1  1  1 

  13 14 15 16     12 13 14 15 16 17 
   1  1  1  0      1  1  1  1  0  0 

  17 18 19 20     16 17 18 19 20 21 
   0  0  0  1      0  0  0  0  1  0 

  21 22 23 24     20 21 22 23 24 25 
   0  0  1  1      1  0  0  1  1  1 

  25 26 27 28     24 25 26 27 28 29 
   1  0  1  0      1  1  0  1  0  0 

  29 30 31 32     28 29 30 31 32 01 
   0  1  1  1      0  0  1  1  1  0 


  5.2 E(R_0) xor k_1
    Then XORed value is splited into 8 6-bit pieces

    E(R_0)  100000000001011111111100000010100111110100001110
       k_1  101000101010110011001001001011000101101110101001
       xor  001000101011101100110101001001100010011010100111
    pieces:
        001000 101011 101100 110101 001001 100010 011010 100111


  5.3 S-boxes
    Example on S-box S_1. Other S-boxes applied similarly

                                piece #1: 001000
    left-most bit | right-most bit (row): 00
                    middle bits (column): 0100
    S_1:
       0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
    00  14    4   13    1    2   15   11    8    3   10    6   12    5    9    0    7
    01   0   15    7    4   14    2   13    1   10    6   12   11    9    5    3    8
    10   4    1   14    8   13    6    2   11   15   12    9    7    3   10    5    0
    11  15   12    8    2    4    9    1    7    5   11    3   14   10    0    6   13

    Substitution chosen: 2
    bin: 10

    All substitutions:
    0010 1111 0011 0101 0100 1110 1010 0111

    S-boxes Output
    bin:
    00101111001101010100111010100111
    hex:
    2f354ea7


  5.4 Permutation P
    This P-box output is f-function output

    S-boxes output          ???  f output = d42e5e3d
  01 02 03 04 05 06 07 08     16 07 20 21 29 12 28 17 
   0  0  1  0  1  1  1  1      1  1  0  1  0  1  0  0 

  09 10 11 12 13 14 15 16     01 15 23 26 05 18 31 10 
   0  0  1  1  0  1  0  1      0  0  1  0  1  1  1  0 

  17 18 19 20 21 22 23 24     02 08 24 14 32 27 03 09 
   0  1  0  0  1  1  1  0      0  1  0  1  1  1  1  0 

  25 26 27 28 29 30 31 32     19 13 30 06 22 11 04 25 
   1  0  1  0  0  1  1  1      0  0  1  1  1  1  0  1 


    f-function output
    bin:
    11010100001011100101111000111101
    hex:
    d42e5e3d


6. L_0 xor f-function output
  XORed value is R_1

  L_0 = ff845f5a

       L_0  11111111100001000101111101011010
  f output  11010100001011100101111000111101
       xor  00101011101010100000000101100111

  R_1 = 2baa0167

```

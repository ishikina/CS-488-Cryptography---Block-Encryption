# CS 488: Cryptography - Block Encryption

### Files

* program1.h - Header file for global variables, class objects, and functions
* main.cpp - main() takes in arguments to either encrypt or decrypt
* encrypt.cpp - Encryption process and functions
* decrypt.cpp - Decryption process and functions
* psu_crypt.cpp - DES process in addition to file read and write functions

### Description

This program encrypt and decrypts strings in a text file uses the PSU-CRYPT algorithm which is a combination of the Twofish and Skipjack algorithms which uses the DES structure. A set of 192 sub keys are generated based on circular rotations of the main key. The plaintext goes through 16 rounds of the Feistel cipher. Bit manipulation operations are performed on the lower half bits of the ciphertext, and each round the ciphertext is permutated through substituions, concatenations, and XORs. 

The key must be 64 bits and text in the external files are processed 64 bits at a time and the resulting block is 64 bits. This is a symetric key system so the encryption and decryption processes are the same, however, the sub keys are used in the reverse order.

*(note: Program is able to encrypt any amount of plaintext successfully, however, bugs arise when attempting to decrypt three or more blocks of ciphertext. For example, if the plaintext was "securitysecurity" (2 blocks), the resulting ciphertext can be correctly decrypted back to "securitysecurity". If the plaintext was "securitysecuritysecurity" (3 blocks), the ciphertext can be correctly generated, however, it cannot be decrypted back to "securitysecuritysecurity".)*

## Running the code

To compile:
```
g++ -o psu-crypt *.cpp
```

To encrypt:
```
./psu-crypt -e input.txt key.txt ciphertext.txt
```

To decrypt:
```
./psu-crypt -d ciphertext.txt key.txt plaintext.txt
```

## References

[GeeksforGeeks](https://www.geeksforgeeks.org/program-to-convert-hexadecimal-number-to-binary/)

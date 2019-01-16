# Spinning Zebra Encryption

This algorithm revolves around the use of matrix multiplication and
XOR. The algorithm has a key size of 213 bits. Detailed explaination of the algorithm [here](SZE.pdf).

## Sample Usage
```bash
~/Projects/SZE
➜ ./sze.py -e 
Plaintext: hello

Ciphertext b85: 2U3@f2a-ZBUl6Z4(_pd2Qe-@ws6FPPlW$W
Key: 1dbf13ab78b8c80a4fec8b71150ac597723320480d04242b0c1c07

~/Projects/SZE
➜ ./sze.py -d
Ciphertext: 2U3@f2a-ZBUl6Z4(_pd2Qe-@ws6FPPlW$W
Key: 1dbf13ab78b8c80a4fec8b71150ac597723320480d04242b0c1c07

Plaintext
hello
```
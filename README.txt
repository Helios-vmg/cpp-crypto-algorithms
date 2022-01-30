This is a library of common cryptographic primitives. The following algorithms
are implemented:
* MD5
* SHA-256
* AES (Rijndael) with 128-, 192-, and 256-bit keys
* Twofish with 128-, 192-, and 256-bit keys
* CTR operation mode to turn both Rijndael and Twofish into stream ciphers
* A cryptographically secure pseudorandom number generator based on block
  ciphers
* Secp256k1

Note that speed was not a priority while implementing the library. The goal was
to have a library with no dependencies, that was easy to use, and which followed
modern C++ practices.
See the test_* files for examples on how to use the facilities.

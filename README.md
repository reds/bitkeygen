bitkeygen
=========

Bitcoin/Litecoin address generator.

Very simple bitcoin/litecoin key/address generator.

Generate a random address and calculate the associated public key.

For linux and mac:
    gcc -o genkey genkey.c -lcrypto && ./genkey


To import the private key into the bitcoin client:
   ./bitcoin importprivkey 5xxxxxxxxx "account name"


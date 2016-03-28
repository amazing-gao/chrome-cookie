#! /bin/bash

# g++ decryptor.cpp -I/usr/local/opt/nspr/include/nspr -I/usr/local/opt/nss/include/nss -L/usr/local/opt/nspr/lib -L/usr/local/opt/nss/lib -l nspr4 -l nss3 -o decryptor -l sqlite3

g++ decryptor.cpp -o decryptor -l sqlite3 -lsqlite3 -lcrypto
# ./decryptor

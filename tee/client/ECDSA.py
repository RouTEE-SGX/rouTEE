import socket
from datetime import datetime
import csv
import sys
# python crypto library example: https://blog.naver.com/chandong83/221886840586
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.IO import PEM
import bitcoin_crypto as bc
import ecdsa
import codecs

user_list = ['alice', 'bob', 'host']

# for user in user_list:
#     sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
#     vk = sk.get_verifying_key()
#     with open("./key/private_key_{}.pem".format(user), "wb") as f:
#         f.write(sk.to_pem())
#     with open("./key/public_key_{}.pem".format(user), "wb") as f:
#         f.write(vk.to_pem())


# ECDSA verify test
with open("./key/private_key_alice.pem") as f:
    sk = ecdsa.SigningKey.from_pem(f.read())

with open("./key/public_key_alice.pem") as f:
    vk = ecdsa.VerifyingKey.from_pem(f.read())

print((vk.pubkey.point.x().to_bytes(32, 'little')))

# message = b"message"
# sig = sk.sign(message)

# try:
#     vk.verify(sig, message)
#     print("good signature")
# except:
#     print("bad signature")


# # generate ECDSA signature
# private_key = ECC.import_key(open('./key/private_key_host.pem').read())
# h = SHA256.new(message)
# signer = DSS.new(private_key, 'fips-186-3')
# signature = signer.sign(h)

# # verify the signature
# public_key = ECC.import_key(open('./key/public_key_host.pem').read())
# h = SHA256.new(message)
# verifier = DSS.new(public_key, 'fips-186-3')
# try:
#     verifier.verify(h, signature)
#     print("The message is authentic.")
# except ValueError:
#     print("The message is not authentic.")

# """ bitcoin_crypto test """
# kg = bc.KeyGenerator()
# bw = bc.BitcoinWallet()
# private_key = kg.generate_key()
# print(private_key)
# public_key = bw.private_to_public(private_key)
# #public_key = bw.private_to_public(codecs.decode("cQumEGX57wMLEqf5MeTPanJr6onhpWr7mvQub1nk98LVpfyh9Ecr", 'hex'))
# print(public_key, type(public_key))
# address = bw.public_to_address(public_key)
# print(address)

# # SECP256k1 is the Bitcoin elliptic curve
# sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
# print(sk)
# vk = sk.get_verifying_key()
# print(vk)
# sig = sk.sign(b"message")
# print(sig)
# vk.verify(sig, b"message") # True

# """ ECDSA test """
# message = b'I give my permission to order #4355'

# private_key = ECC.import_key(open('myprivatekey.pem').read())
# h = SHA256.new(message)
# signer = DSS.new(private_key, 'fips-186-3')
# signature = signer.sign(h)

# public_key = ECC.import_key(open('mypublickey.pem').read())
# h = SHA256.new(message)
# verifier = DSS.new(public_key, 'fips-186-3')
# try:
#     verifier.verify(h, signature)
#     print("The message is authentic.")
# except ValueError:
#     print("The message is not authentic.")


# f = open('../Enclave/routee_private.pem','wt')
# f.write(private_key.export_key(format='PEM'))
# f.close()
# print(private_key)


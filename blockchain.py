# import libraries
import hashlib
import random
import string
import json
import binascii
import numpy as np
import pandas as pd
import pylab as pl
import logging
import datetime
import collections

# import PKI libraries
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Client:
    """
        A class used to generate the private and public keys using a built-in Python RSA algorithm.
        A client can be both a sender or a recipient of the money.
    """
    def __init__(self):
        random = Crypto.Random.new().read
        # private key can be stored securely on an external storage or can be written down as the ASCII representation  
        self._private_key = RSA.generate(1024, random)
        # public key is the client's identity
        self._public_key = self._private_key.publickey()
        # the signer
        self._signer = PKCS1_v1_5.new(self._private_key)

    # return the HEX representation of the public key
    @property
    def identity(self):
        return binascii.hexlify(self._public_key.exportKey(format='DER')).decode('ascii')

class Transaction:
    """
    A class allows a client to send money to another client.
    A sender creates a transation and specifies public address of the recipient.
    
    """
    def __init__(self, sender, recipient, value):
        # the sender’s public key, 
        self.sender = sender
        # the recipient’s public key
        self.recipient = recipient
        # the amount to be sent
        self.value = value
        # the time of a transaction
        self.time = datetime.datetime.now()

    # convert a transaction to dict
    def to_dict(self):
        # the first block in the blockchain is a Genesis block
        # it contains the first transaction initiated by the creator of the blockchain
        if self.sender == "Genesis":
            identity = "Genesis"
        else:
            identity = self.sender.identity

        # the entire transaction information
        return collections.OrderedDict({
            'sender': identity,
            'recipient': self.recipient,
            'value': self.value,
            'time' : self.time
        })

    # sign the dictionary object using the private key of the sender usinf use the built-in PKI with SHA algorithm
    # the generated signature is decoded to get the ASCII representation for printing and storing it in the blockchain
    def sign_transaction(self):
        private_key = self.sender._private_key
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    # display transaction
    def  __str__(self):
        dict = self.to_dict()
        return "sender: " + dict['sender'] + '\n-----\n' \
                    "recipient: " + dict['recipient'] + '\n-----\n' \
                    "value: " + str(dict['value']) +  '\n-----\n' \
                    "time: " + str(dict['time']) + '\n-----\n'

# create transactions
transaction_list = []
# Testing client
client_list = []
# create clients
for count in range(0, 10):
    client_list.append(Client())
# create random transactons
for count in range(0, 10):
    #print("Transaction #%d" % (count + 1))
    sender = random.choice(client_list)
    recipient = random.choice(client_list)
    value = random.randint(0, 100)
    if sender != recipient:
        transaction = Transaction(
                sender,                 # the sender
                recipient.identity,     # public key of the recipient
                value                   # the amount
            )
        transaction_list.append(transaction)
        # generate and print the signature
        signature = transaction.sign_transaction()
        #print(signature)

# display transaction queue
for t in transaction_list:
    print(t)

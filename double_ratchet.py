import os
import hashlib
import base64
import pyDH
from typing import Tuple
from Crypto.Cipher import AES
import hkdf

def get_dh_obj():
    return pyDH.DiffieHellman()

def b64enc(b):
    return base64.b64encode(b).decode("utf-8")

def b64dec(b):
    return base64.b64decode(b)


def str_to_bytes(s:str) -> bytes:
    return s.encode('utf-8')

def bytes_to_str(b:bytes) -> str:
    return b.decode('utf-8')

def kdf_rk(rk:bytes, dh_output:str) -> Tuple[bytes, bytes]:
    prk = hkdf.Hkdf(b"DoubleRatchet", rk, hashlib.sha256)
    output = prk.expand(str_to_bytes(dh_output), 64)
    return (output[:32], output[32:])

def kdf_ck(ck:bytes) -> Tuple[bytes, bytes]:
    prk = hkdf.Hkdf(b"DoubleRatchet",ck, hashlib.sha256)
    output = prk.expand(b"ChainKey", 64)
    return (output[:32], output[32:])


class DoubleRatchet():
    
    def __init__(self):
        
        self.our_dh_obj = get_dh_obj()
        self.their_public_key = None
        self.root_key = None
        self.recv_key = None
        self.send_key = None
        self.last_done = None
        self.root_chain = None

    #function to initialize the double ratchet
    def initialize(self, root_key:bytes, their_public_key:int) -> None:
        self.root_key = root_key
        self.their_public_key = their_public_key
        self.root_chain = hkdf.Hkdf(b"DoubleRatchet", self.root_key , hashlib.sha256)
        print("Initialized Diffie Hellman ratchet with root key and receiver public key")

    
    #function to refresh the chains with new keys derived from the root send and receive keys
    def refresh_chains(self) -> None:
        self.recv_chain = hkdf.Hkdf(b"DoubleRatchet", self.recv_key, hashlib.sha256)
        self.send_chain = hkdf.Hkdf(b"DoubleRatchet", self.send_key , hashlib.sha256)
        print("Chains are updated")

    def chain_step(self, chain:str) -> bytes: #input should be either "send" or "receive"
        if chain == "send":
            output = self.send_chain.expand(b"common_key", 64)
            self.send_key = output[:32]
            self.refresh_chains()
            return output[32:]
        elif chain == "receive":
            output = self.recv_chain.expand(b"common_key", 64)
            self.recv_key = output[:32]
            self.refresh_chains()
            return output[32:]
        else:
            raise Exception("Invalid chain")
    
    #function to update the key pair
    def update_key_pair(self) -> int:
        self.our_dh_obj = get_dh_obj()
        return self.our_dh_obj.gen_public_key()

    def update_root(self) -> bytes:
        self.root_key, output = kdf_ck(self.root_key)
        self.root_chain = hkdf.Hkdf(b"DoubleRatchet", self.root_key, hashlib.sha256)
        return output
    
    #function that returns Tuple containing key to encrypt and new public key as integer
    def send(self) -> Tuple[bytes, int or None]:
        print("Generating sending encryption key along with new public key")
        if self.last_done == None:
            self.last_done = "send"
            dh_output = self.our_dh_obj.gen_shared_key(self.their_public_key)
            (self.root_key, self.send_key) = kdf_rk(self.root_key, dh_output)
            self.refresh_chains()
            output = self.chain_step("send")
            public_key = self.our_dh_obj.gen_public_key()
            return (output, public_key)
        
        elif self.last_done == "recv":
            self.last_done = "send"
            new_pub = self.update_key_pair()
            dh_output = self.our_dh_obj.gen_shared_key(self.their_public_key)
            (self.root_key, self.send_key) = kdf_rk(self.root_key, dh_output)
            self.refresh_chains()
            key = self.chain_step("send")
            return (key, new_pub) #(the key to encrypt the data, new public key)
        
        elif self.last_done == "send":
            self.last_done = "send"
            output = self.chain_step("send")
            return (output, None) #Here second value is None because the same person is sending again
        
    
    def recv(self, public_key) -> bytes:
        print("Generating receiving decryption key")
        if public_key != None:
            self.their_public_key = public_key
        if self.last_done == None:
            self.last_done = "recv"
            dh_output = self.our_dh_obj.gen_shared_key(self.their_public_key)
            self.root_key, self.recv_key = kdf_rk(self.root_key, dh_output)
            self.refresh_chains()
            output = self.chain_step("receive")
            return output
        elif self.last_done == "send":
            self.last_done = "recv"
            dh_output = self.our_dh_obj.gen_shared_key(self.their_public_key)
            self.root_key, self.recv_key = kdf_rk(self.root_key, dh_output)
            self.refresh_chains()
            output = self.chain_step("receive")
            return output
        elif self.last_done == "recv":
            self.last_done = "recv"
            output = self.chain_step("receive")
            return output

# def main():
#     alice = DoubleRatchet()
#     bob = DoubleRatchet()
#     root_key = os.urandom(32)
#     alice.initialize(root_key, bob.update_key_pair())
#     ret = alice.send()
#     alice_send_enc = ret[0]
#     alice_new_pub = ret[1]
    
#     print("Alice's send key: ", alice_send_enc)
#     print("Alice's new public key: ", alice_new_pub)

#     bob.initialize(root_key, alice_new_pub)
#     ret = bob.recv(alice_new_pub)
#     bob_recv_enc = ret
#     print("Bob's receive key: ", bob_recv_enc)


# if __name__ == "__main__":
#     main()
from cryptography.hazmat.primitives.asymmetric import x25519
import axolotl_curve25519 as curve
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256,HMAC
from cryptography.hazmat.primitives import serialization
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import json
import os
from server import Server

MAX_OPK_NUM=1
KDF_F = b'\xff' * 32
KDF_LEN = 32
KDF_SALT = b'\0' * KDF_LEN
# Length definition for hello message encryption
AES_N_LEN = 16
AES_TAG_LEN =16
EC_KEY_LEN = 32

server=Server()

class User():

    def __init__(self, name, MAX_OPK_NUM=MAX_OPK_NUM):
        self.name = name
        self.IK_s = x25519.X25519PrivateKey.generate()
        self.IK_p = self.IK_s.public_key()
        self.SPK_s = x25519.X25519PrivateKey.generate()
        self.SPK_p = self.SPK_s.public_key()
        self.SPK_sig = self.sign(self.IK_s,self.dump_publickey(self.SPK_p))
        self.OKPs = []
        self.OPKs_p = []
        for _ in range(MAX_OPK_NUM):
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            self.OPKs_p.append(pk)
            self.OKPs.append((sk, pk))
            #  for later steps
        self.key_bundles = {}
        self.dr_keys= {}

    def publish(self):
        bundle= {
          'IK_p': self.dump_publickey(self.IK_p),
          'SPK_p': self.dump_publickey(self.SPK_p),
          'SPK_sig': self.SPK_sig,
          'OPK_p': self.dump_publickey(self.OPKs_p[0])  #Only one key is send
        }
        server.publish(self.name,bundle)
        
        
      
    
 # Get key bundle from a server object
    def get_key_bundle(self,user_name):
        if user_name in self.key_bundles and user_name in self.dr_keys:
            print('Already stored ' + user_name + ' locally, no need handshake again')
            return False

        self.key_bundles[user_name] = server.get_key_bundle(user_name)
        return True

    def initial_handshake(self,user_name):
        if self.get_key_bundle(user_name):
      	    # Generate Ephemeral Key
            sk = x25519.X25519PrivateKey.generate()
            self.key_bundles[user_name]['EK_s'] = sk
            self.key_bundles[user_name]['EK_p'] = sk.public_key()

            #Converting bytes to objects
            self.key_bundles[user_name]['IK_p'] = x25519.X25519PublicKey.from_public_bytes(self.key_bundles[user_name]['IK_p'])
            self.key_bundles[user_name]['SPK_p'] = x25519.X25519PublicKey.from_public_bytes(self.key_bundles[user_name]['SPK_p'])
            self.key_bundles[user_name]['OPK_p'] = x25519.X25519PublicKey.from_public_bytes(self.key_bundles[user_name]['OPK_p'])

    def x3dh_KDF(self,key_material):
        km = KDF_F + key_material
        return HKDF(km, KDF_LEN, KDF_SALT, SHA256, 1)

    def generate_send_secret_key(self, user_name):

        key_bundle = self.key_bundles[user_name]

        DH_1 = self.IK_s.exchange(key_bundle['SPK_p'])
        DH_2 = key_bundle['EK_s'].exchange(key_bundle['IK_p'])
        DH_3 = key_bundle['EK_s'].exchange(key_bundle['SPK_p'])
        DH_4 = key_bundle['EK_s'].exchange(key_bundle['OPK_p'])

        if not self.verify(key_bundle['IK_p'],self.dump_publickey(key_bundle['SPK_p']),key_bundle['SPK_sig']):
            print('Unable to verify Signed Prekey')
            return
        else:
            print('Prekey successfully verified')

        # create SK
        key_bundle['SK'] = self.x3dh_KDF(DH_1 + DH_2 + DH_3 + DH_4)
        print("Secret Key : ",key_bundle['SK'])
    
    def dump_privatekey(self,private_key):
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key

    def dump_publickey(self,public_key):
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_key

    def build_x3dh_hello(self,to, ad):
        # Binary additional data
        b_ad = (json.dumps({
          'from': self.name,
          'to': to,
          'message': ad
        })).encode('utf-8')

        key_bundle = self.key_bundles[to]
        # 64 byte signature
        key_comb = self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['EK_p']) +self.dump_publickey(key_bundle['OPK_p'])
        signature = self.sign(self.IK_s, key_comb + b_ad)
        global EC_SIGN_LEN
        EC_SIGN_LEN=len(signature)
        print("Alice message signature: ", signature)
        print("data: ", key_comb + b_ad)

        # 16 byte aes nonce
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(key_bundle['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(signature + self.dump_publickey(self.IK_p) + self.dump_publickey(key_bundle['IK_p']) + b_ad)

        # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
        message = key_comb + nonce + tag + ciphertext

        server.send(self.name,to,message)

        # For Double Ratchet
        self.dr_state_initialize(to, key_bundle['SK'], [key_bundle['EK_s'], key_bundle['EK_p']], "")
    
      # Continue in Class Client
    def recv_x3dh_hello_message(self):

        # receive the hello message
        sender, recv = server.get_message(self.name)
        
        if sender=='none':
            print('sender is none in recv_x3dh_hello_message')
            exit(1)
        else:
            print('Sender: ',sender)

        self.get_key_bundle(sender)

        key_bundle = self.key_bundles[sender]

        IK_pa = recv[:EC_KEY_LEN]
        EK_pa = recv[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = recv[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = recv[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = recv[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = recv[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        # Verify if the key in hello message matches the key bundles from server
        if (IK_pa != key_bundle['IK_p']):
            print("Key in hello message doesn't match key from server")
            return

        
        #convert from bytes to  object
        key_bundle['IK_p'] = x25519.X25519PublicKey.from_public_bytes(key_bundle['IK_p'])
        key_bundle['SPK_p'] = x25519.X25519PublicKey.from_public_bytes(key_bundle['SPK_p'])
        key_bundle['OPK_p'] = x25519.X25519PublicKey.from_public_bytes(key_bundle['OPK_p'])

        # Verify Signed pre key from server
        if not self.verify(key_bundle['IK_p'],self.dump_publickey(key_bundle['IK_p']),key_bundle['SPK_sig']):
            print('Unable to verify Signed Prekey')
            return

        sk = self.generate_recv_secret_key(IK_pa, EK_pa, OPK_pb)
        print('bob sk: ', sk)

        if sk is None:
          return

        key_bundle['SK'] = sk
        message = self.x3dh_decrypt_and_verify(key_bundle, IK_pa, EK_pa, nonce, tag, ciphertext,OPK_pb)

        # For Double Ratchet
        self.dr_state_initialize(sender, sk, [], EK_pa)

        # Get Ek_pa and plaintext ad
        return EK_pa, message


    def search_OPK_lst(self,OPK_pb):

        list=self.OKPs

        for sk,pk in list:
            if pk==OPK_pb:
                return sk
        return None


    def generate_recv_secret_key(self, IK_pa, EK_pa, OPK_pb):

        # Find corresponding secret OPK secret key
        # And remove the pair from the list
        OPK_sb = self.search_OPK_lst(OPK_pb)
        if OPK_sb is None:
          return

        IK_pa = x25519.X25519PublicKey.from_public_bytes(IK_pa)
        EK_pa = x25519.X25519PublicKey.from_public_bytes(EK_pa)

        DH_1 = self.SPK_s.exchange(IK_pa)
        DH_2 = self.IK_s.exchange(EK_pa)
        DH_3 = self.SPK_s.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        # create SK
        return self.x3dh_KDF(DH_1 + DH_2 + DH_3 +DH_4)

    def x3dh_decrypt_and_verify(self, key_bundle, IK_pa, EK_pa, nonce, tag, ciphertext,OPK_pb):
        # Decrypt cipher text and verify
        cipher = AES.new(key_bundle['sk'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        try:
            p_all = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print('Unable to verify/decrypt ciphertext')
            return
        except Exception as e:
            print(e)
            return

        # Byte format of plain text
        sign = p_all[:EC_SIGN_LEN]
        IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
        IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
        ad = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]

        if (IK_pa != IK_pa_p and self.IK_p != IK_pb_p):
            print("Keys from header and ciphertext not match")
            return

        if not self.verify(IK_pa,IK_pa_p + EK_pa + OPK_pb + ad,sign):
            print("Unable to verify the message signature")
            return

        print('Message: ', json.loads(ad))
        return json.loads(ad)

    # double rachet
    def dr_state_initialize(self, user_name, RK, DH_pair, DH_p):
        self.dr_keys[user_name] = {
            "RK": RK,
            "DH_pair": DH_pair,
            "DH_p": DH_p,
            "CKs": [],
            "CKr": [],
            "Ns": 0,
            "Nr": 0,
            "PN": 0
        }

    def KDF_RK(self,rk, dh_out):
        out = HKDF(dh_out, 64, rk, SHA256, 1)

        rk_input_material = out[:32]
        ck = out[32:]
        return rk_input_material, ck
    
    def KDF_CK(self,ck):
        ck_input_material = HMAC.new(ck, digestmod=SHA256).update(b'\x01').digest()
        mk = HMAC.new(ck, digestmod=SHA256).update(b'\x02').digest()
        return ck_input_material, mk



    def sign(self,private_key,message):
        randm64=os.urandom(64)
        private_key=self.dump_privatekey(private_key)
        return curve.calculateSignature(randm64,private_key,message)



    def verify(self,public_key,message,signature):
        public_key=self.dump_publickey(public_key)
        k=curve.verifySignature(public_key,message,signature)
        return k==0

        


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


KDF_F = b'\xff' * 32
KDF_LEN = 32
KDF_SALT = b'\0' * KDF_LEN
# Length definition for hello message encryption
AES_N_LEN = 16
AES_TAG_LEN =16
EC_KEY_LEN = 32

server=Server()


#public keys are stored as bytes and private keys as objects

class User():

    def __init__(self, name, MAX_OPK_NUM=1):
        self.name = name
        self.IK_s = x25519.X25519PrivateKey.generate()
        self.IK_p = self.dumpPublickey(self.IK_s.public_key())
        self.SPK_s = x25519.X25519PrivateKey.generate()
        self.SPK_p = self.dumpPublickey(self.SPK_s.public_key())
        self.SPK_sig = self.sign(self.IK_s,self.SPK_p)
        self.OPKs = []
        self.OPKs_p = []
        for _ in range(MAX_OPK_NUM):
            sk = x25519.X25519PrivateKey.generate()
            pk = self.dumpPublickey(sk.public_key())
            self.OPKs_p.append(pk)
            self.OPKs.append((sk, pk))
            #  for later steps
        self.key_bundles = {}
        self.dr_keys= {}
    
    def publish(self):
        bundle= {
          'IK_p': self.IK_p,
          'SPK_p': self.SPK_p,
          'SPK_sig': self.SPK_sig,
          'OPK_p': self.OPKs_p  #all keys are send
        }
        server.publish(self.name,bundle)


 # Get key bundle from a server object
    def getKeyBundle(self,user_name :str) -> bool:
        if user_name in self.key_bundles and user_name in self.dr_keys:
            print(f'Already stored  {user_name} locally, no need handshake again')
            return False

        self.key_bundles[user_name] = server.get_key_bundle(user_name)

        if self.key_bundles[user_name] is None:
            print(f"Error : User {user_name} does not exist")
            exit(1)
        return True


    def initialHandshake(self,user_name):
        if self.getKeyBundle(user_name):

            key_bundle=self.key_bundles[user_name]

            if self.verify(key_bundle['IK_p'],key_bundle['SPK_p'],key_bundle['SPK_sig']):
                print(f'Prekey of {user_name} successfully verified')
            else:
                print(f'Unable to verify Signed Prekey of {user_name}')
                exit(1)

      	    # Generate Ephemeral Key
            sk = x25519.X25519PrivateKey.generate()
            self.key_bundles[user_name]['EK_s'] = sk
            self.key_bundles[user_name]['EK_p'] = self.dumpPublickey(sk.public_key())


    def x3dh_KDF(self,key_material):
        km = KDF_F + key_material
        return HKDF(km, KDF_LEN, KDF_SALT, SHA256, 1)


    def generateSendSecretKey(self, user_name):
        key_bundle = self.key_bundles[user_name]

        SPK_p=x25519.X25519PublicKey.from_public_bytes(key_bundle['SPK_p'])
        IK_p=x25519.X25519PublicKey.from_public_bytes(key_bundle['IK_p'])

        DH_1 = self.IK_s.exchange(SPK_p)
        DH_2 = key_bundle['EK_s'].exchange(IK_p)
        DH_3 = key_bundle['EK_s'].exchange(SPK_p)
        DH_4=""

        if key_bundle['OPK_p'] !=KDF_F:   #checking whether the all prekeys are used up
            OPK_p=x25519.X25519PublicKey.from_public_bytes(key_bundle['OPK_p'])
            DH_4 = key_bundle['EK_s'].exchange(OPK_p)

        # create SK
        if len(DH_4)!=0 :
            key_bundle['SK'] = self.x3dh_KDF(DH_1 + DH_2 + DH_3 + DH_4)
        else:
            key_bundle['SK'] = self.x3dh_KDF(DH_1 + DH_2 + DH_3)

        print("Secret Key : ",key_bundle['SK'])

        #Delete ephemeral private key
        self.key_bundles[user_name]['EK_s'] = ""



    def sendInitialMessage(self,to: str, ad: str):
        # Binary additional data
        key_bundle = self.key_bundles[to]

        b_ad = (json.dumps({
          'from': self.name,
          'to': to,
          'message': ad
        })).encode('utf-8')

        # 64 byte signature
        key_comb = self.IK_p+key_bundle['EK_p']+key_bundle['OPK_p']

        signature = self.sign(self.IK_s, key_comb + b_ad)
        global EC_SIGN_LEN
        EC_SIGN_LEN=len(signature)
        print("Alice message signature: ", signature)
        print("Data: ", key_comb + b_ad)

        # 16 byte aes nonce
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(key_bundle['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(signature + self.IK_p+ key_bundle['IK_p']+ b_ad)

        # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
        message = key_comb + nonce + tag + ciphertext

        print(f"Message sent : {message}")

        server.send(self.name,to,message)

        # For Double Ratchet
        self.dr_state_initialize(to, key_bundle['SK'], [key_bundle['EK_s'], key_bundle['EK_p']], "")



    def recvInitialMessage(self) -> tuple[bytes,str]:

        # receive the hello message
        sender, recv = server.get_message(self.name)
        if sender=='none':
            print('No new messages')
            exit(1)
        else:
            print(f'Received Message from {sender}')

        self.getKeyBundle(sender)

        key_bundle = self.key_bundles[sender]

        IK_pa = recv[:EC_KEY_LEN]
        EK_pa = recv[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = recv[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = recv[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = recv[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = recv[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        # Verify if the key in hello message matches the key bundles from server
        if (IK_pa != key_bundle['IK_p']):
            print(f"Key in initial message from {sender} doesn't match key from server")
            exit(1)

        

        # Verify Signed pre key from server
        if not self.verify(key_bundle['IK_p'],key_bundle['SPK_p'],key_bundle['SPK_sig']):
            print(f'Unable to verify signed prekey of {sender} from server')
            exit(1)


        sk = self.generateRecvSecretKey(IK_pa, EK_pa, OPK_pb)
        print('Receiver Secret Key: ', sk)


        key_bundle['sk'] = sk
        message = self.decryptAndVerify(key_bundle, IK_pa, EK_pa, nonce, tag, ciphertext,OPK_pb)

        # For Double Ratchet
        self.dr_state_initialize(sender, sk, [], EK_pa)

        # Get Ek_pa and plaintext ad
        return EK_pa, message



    def decryptAndVerify(self, key_bundle :dict, IK_pa :bytes, EK_pa : bytes, nonce : bytes, tag : bytes, ciphertext : bytes, OPK_pb: bytes) -> str:
        # Decrypt cipher text and verify
        cipher = AES.new(key_bundle['sk'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        try:
            p_all = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print('Unable to verify/decrypt ciphertext')
            exit(1)
        except Exception as e:
            print(e)
            exit(1)

        # Byte format of plain text
        sign = p_all[:EC_SIGN_LEN]
        IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
        IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
        ad = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]


        if IK_pa != IK_pa_p:
            print("Identity Keys of sender does not match from header and cipher text.")        
            exit(1)


        if self.IK_p != IK_pb_p:
            print("Identity Keys of receiver does not match from header and cipher text.")        
            exit(1)


        if not self.verify(IK_pa,IK_pa_p +EK_pa+ OPK_pb+ ad,sign):
            print("Unable to verify the message signature")
            exit(1)

        print('Message: ', json.loads(ad))
        return json.loads(ad)






    def generateRecvSecretKey(self, IK_pa : bytes, EK_pa : bytes, OPK_pb : bytes):

        # Find corresponding secret OPK secret key
        # And remove the pair from the list

        IK_pa_obj = x25519.X25519PublicKey.from_public_bytes(IK_pa)
        EK_pa_obj = x25519.X25519PublicKey.from_public_bytes(EK_pa)

        DH_1 = self.SPK_s.exchange(IK_pa_obj)
        DH_2 = self.IK_s.exchange(EK_pa_obj)
        DH_3 = self.SPK_s.exchange(EK_pa_obj)

        if OPK_pb!=KDF_F:
            OPK_sb = self.search_OPK_lst(OPK_pb)
            if OPK_sb is None:
                print("OPK not found in key bundle")
                exit(1)
            else:
                print("Found OPK")
                DH_4 = OPK_sb.exchange(EK_pa_obj)
                return self.x3dh_KDF(DH_1 + DH_2 + DH_3 +DH_4)
        else:
                return self.x3dh_KDF(DH_1 + DH_2 + DH_3)









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

    def search_OPK_lst(self,OPK_pb : bytes) -> x25519.X25519PrivateKey | None:

        list=self.OPKs

        for sk,pk in list:
            if pk == OPK_pb:
                return sk
        return None


    def dumpPrivatekey(self,private_key) -> bytes:
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key

    def dumpPublickey(self,public_key) -> bytes:
        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_key


    def sign(self,private_key,message) -> bytes:
        randm64=os.urandom(64)
        private_key=self.dumpPrivatekey(private_key)
        return curve.calculateSignature(randm64,private_key,message)



    def verify(self,public_key,message,signature) -> bool:
        #public_key=self.dumpPublickey(public_key)
        k=curve.verifySignature(public_key,message,signature)
        return k==0


    def KDF_RK(self,rk, dh_out):
        out = HKDF(dh_out, 64, rk, SHA256, 1)

        rk_input_material = out[:32]
        ck = out[32:]
        return rk_input_material, ck
    
    def KDF_CK(self,ck):
        ck_input_material = HMAC.new(ck, digestmod=SHA256).update(b'\x01').digest()
        mk = HMAC.new(ck, digestmod=SHA256).update(b'\x02').digest()
        return ck_input_material, mk
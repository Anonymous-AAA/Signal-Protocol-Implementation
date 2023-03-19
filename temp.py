from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import axolotl_curve25519 as curve
import os

randm32 = os.urandom(32)
randm64 = os.urandom(64)


def dump_privatekey(private_key):
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key


def dump_publickey(public_key):
    public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_key



IK_s=x25519.X25519PrivateKey.generate()
IK_p=IK_s.public_key()

private_key=dump_privatekey(IK_s)
public_key=dump_publickey(IK_p)
message=dump_publickey(IK_p)



signature = curve.calculateSignature(randm64, private_key, message)

verified = curve.verifySignature(public_key, message, signature)
print(verified)

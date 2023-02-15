import json, logging
import hashlib, binascii, ecdsa, ed25519
from uuid import UUID
from requests import codes, Response
from datetime import datetime, timedelta
from jks import jks, AlgorithmIdentifier, rfc5208, TrustedCertEntry

import ubirch
from ubirch.ubirch_protocol import UNPACKED_UPP_FIELD_PREV_SIG, UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

# ================================================== #
# This helper implements ubirch.protocol WITHOUT     #
#       needing to store to an KeyStore file         # 
# ================================================== #

# create a global logger
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()

class ED25519Certificate(TrustedCertEntry):
    """!
    A ED25519 Certificate
    """

    def __init__(self, alias: str, verifying_key: ed25519.VerifyingKey, **kwargs):
        super().__init__(**kwargs)
        self.alias = alias
        self.cert = verifying_key.to_bytes()
        self.timestamp = int(datetime.utcnow().timestamp())

class ECDSACertificate(TrustedCertEntry):
    """!
    A ECDSA Certificate
    """

    def __init__(self, alias: str, verifying_key: ecdsa.VerifyingKey, **kwargs):
        super().__init__(**kwargs)
        self.alias = alias
        self.cert = verifying_key.to_string()
        self.timestamp = int(datetime.utcnow().timestamp())

class Proto(ubirch.Protocol):
    """!
    Implement the ubirch-protocol, including creating and saving signatures.
    Actually a wrapper around 'ubirch.Protocol' to be accessible using the ubirch.KeyStore.
    Most of the functions are called from inside ubirch.Protocol.
    For that reason _sign() and _verify() are overloaded and implemented here.
    """

    def __init__(self, uuid: UUID, key_type: str, sk: str) -> None:
        super().__init__()
        logger.info("ubirch-protocol device id: {}".format(uuid))
        self.key_type = key_type

        # check the key type before creating new keys
        if key_type == "ed25519":
            self.sk = ed25519.SigningKey(sk.encode(), encoding='hex')
            self.vk = self.sk.get_verifying_key()
            self.certObj = ED25519Certificate(uuid.hex, self.vk)

            logger.info("loaded private key with ed25519 algorithm")

        elif key_type == "ecdsa":
            self.sk = ecdsa.SigningKey.from_string(binascii.unhexlify(sk), curve=ecdsa.curves.NIST256p, hashfunc=hashlib.sha256)
            self.vk = self.sk.get_verifying_key()
            self.certObj = ECDSACertificate(uuid.hex, self.vk)

            logger.info("loaded private key with ecdsa algorithm")

        else:
            raise ValueError(f"unknown key type: {key_type}")
    

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        if isinstance(self.sk, ecdsa.SigningKey):
            final_message = message # no hashing required here

        elif isinstance(self.sk, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest()

        return self.sk.sign(final_message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        if isinstance(self.vk, ecdsa.VerifyingKey):
            final_message = message # no hashing required here

        elif isinstance(self.vk, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest()

        return self.vk.verify(signature, final_message)

    def get_vk(self) -> bytes:
        if self.key_type == "ed25519":
            return self.vk.to_bytes()
            
        elif self.key_type == "ecdsa":
            return self.vk.to_string()
        else:
            raise Exception(f"unknown key type: {type}")

    def get_certificate(self, uuid: UUID, validityInDays : int = 3650) -> dict or None:
            """! Get the public key info for key registration"""
            cert = self.certObj

            # set the timestamps (validity = +10 years)
            # TODO set propper validity timestamp
            created = datetime.fromtimestamp(cert.timestamp)
            not_before = datetime.fromtimestamp(cert.timestamp)
            not_after = created + timedelta(days=validityInDays)
            
            # set the alogrithm
            if type(cert) == ED25519Certificate:
                algo = 'ECC_ED25519'
            elif type(cert) == ECDSACertificate:
                algo = 'ecdsa-p256v1'
            else:
                raise Exception("Unexpected certificate class %s" % str(cert.__class__))

            return {
                "algorithm": algo,
                "created": int(created.timestamp()),
                "hwDeviceId": uuid.bytes,
                "pubKey": cert.cert,
                "pubKeyId": cert.cert,
                "validNotAfter": int(not_after.timestamp()),
                "validNotBefore": int(not_before.timestamp())
            }

# ubirch_keys_and_uuids
UBIRCH_UUIDS = {
    "dev": UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff"),  # NOTE: dev environment is not reliable
    "demo": UUID(hex="07104235-1892-4020-9042-00003c94b60b"),
    "prod": UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
}

UBIRCH_PUBKEYS_ED = {
    "dev": ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding="hex"),
    "demo": ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding="hex"),
    "prod": ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding="hex")
}

UBIRCH_PUBKEYS_EC = {
    "dev": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "2e753c064bc671940fcb98165542fe3c70340cff5d53ad47f0304ef2166f4f223b9572251b5fe8aee54c4fb812da79590caf501beba0911b7fcd3add2eb0180c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
    "demo": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "c66fa222898146347741dbcb26b184d4e06cddb01ff04238f457e006b891937ea7e115185fed2c9ab60af2d66497a2e1aedf65ce38941ab5c68a3468544f948c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
    "prod": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "a49758a0937437741314c0558d955089ed61860ba64154f2da45fd23b9178d2ca8225e3410e6bd317db848100004157bc55d88162d4a58c9c2d5a2ce22f3908d"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
}

#! /usr/bin/env python3
#
# Copyright (c) 2018 ubirch GmbH.
#
# @author Matthias L. Jugel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import time
from abc import ABC
from datetime import datetime, timedelta
from uuid import UUID, uuid5

import ecdsa as ecdsa
import ed25519
import requests
import ubirch
from ubirch import API
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

import c8y_client

LOGLEVEL = os.getenv("LOGLEVEL", "DEBUG").upper()
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=LOGLEVEL)
logger = logging.getLogger()

ERRORS = 0

UBIRCH_ENV = os.getenv("UBIRCH_ENV")
SERVER_PUBKEY = os.getenv("SERVER_PUBKEY")
TEST_UUID = os.getenv("TEST_UUID")
TEST_KEY_EDDSA = os.getenv("TEST_KEY_EDDSA")
TEST_KEY_ECDSA = os.getenv("TEST_KEY_ECDSA")
NEO4J_URL = os.getenv("NEO4J_URL")
NEO4J_AUTH = os.getenv("NEO4J_AUTH")
C8Y_AUTH = os.getenv("C8Y_AUTH")


logger.debug(f"UBIRCH_ENV      = '{UBIRCH_ENV}'")
logger.debug(f"NEOJ4_URL       = '{NEO4J_URL}'")
logger.debug(f"NEOJ4_AUTH      = '{NEO4J_AUTH}'")
logger.debug(f"TEST_UUID       = '{TEST_UUID}'")
logger.debug(f"SERVER_PUBKEY   = '{SERVER_PUBKEY}'")
logger.debug(f"TEST_KEY_EDDSA  = '{TEST_KEY_EDDSA}'")
logger.debug(f"TEST_KEY_ECDSA  = '{TEST_KEY_ECDSA}'")
logger.debug(f"C8Y_AUTH        = '{C8Y_AUTH}'")


class Proto(ubirch.Protocol, ABC):
    SERVER_EDDSA_KEY = SERVER_PUBKEY or "a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66"

    def __init__(self, uuid: UUID) -> None:
        super().__init__()
        self.__vk_server = ed25519.VerifyingKey(self.SERVER_EDDSA_KEY, encoding='hex')

    def update_key(self, uuid: UUID, key: str, type: str):
        if type == "ECC_ED25519":
            self.sk = ed25519.SigningKey(key.encode(), encoding='hex')
        elif type == "ecdsa-p256v1":
            self.sk = ecdsa.SigningKey.from_string(binascii.unhexlify(key),
                                                   curve=ecdsa.curves.NIST256p,
                                                   hashfunc=hashlib.sha256)
        else:
            raise Exception(f"unknown key type: {type}")
        self.vk = self.sk.get_verifying_key()
        self.type = type
        self.uuid = uuid

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.sk.sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__vk_server.verify(signature, message)

    def get_vk(self) -> bytes:
        if self.type == "ECC_ED25519":
            return self.vk.to_bytes()
        elif self.type == "ecdsa-p256v1":
            return self.vk.to_string()
        else:
            raise Exception(f"unknown key type: {type}")

    def get_certificate(self) -> dict or None:
        vk = self.get_vk()
        timestamp = int(datetime.utcnow().timestamp())
        created = datetime.fromtimestamp(timestamp)
        not_before = datetime.fromtimestamp(timestamp)
        # TODO fix handling of key validity
        not_after = created + timedelta(days=365)
        return {
            "algorithm": self.type,
            "created": int(created.timestamp()),
            "hwDeviceId": self.uuid.bytes,
            "pubKey": vk,
            "pubKeyId": vk,
            "validNotAfter": int(not_after.timestamp()),
            "validNotBefore": int(not_before.timestamp())
        }

# Device Test UUID
DEVICE_UUID = UUID(hex="FFFF160c-6117-5b89-ac98-15aeb52655e0")
logger.info(f"** UUID: {DEVICE_UUID}")

api = API(auth=os.getenv("UBIRCH_AUTH"), env='dev', debug=True)
protocol = Proto(DEVICE_UUID)

MESSAGES = []

def run_tests(api, proto, uuid, key, type) -> int:
    proto.update_key(uuid, key, type)

    # register the key
    #msg = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, proto.get_certificate())
    # if not api.is_identity_registered(uuid):
    #     logger.info(api.register_identity(msg))

    # TODO: this is here, because the key server does not yet understand ubirch-protocol v2
    if not api.is_identity_registered(uuid):
        pubKeyInfo = proto.get_certificate()
        # create a json key registration request
        pubKeyInfo['hwDeviceId'] = str(uuid)
        pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
        pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
        pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat() + ".000Z")
        pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat() + ".000Z")
        pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat() + ".000Z")

        signable_json = json.dumps(pubKeyInfo, separators=(',', ':')).encode()
        logger.info(signable_json)
        signed_message = proto._sign(uuid, signable_json)
        signature = base64.b64encode(signed_message).decode()
        pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
        pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
        logger.info(pubKeyRegMsgJson)
        logger.info(api.register_identity(pubKeyRegMsgJson).content.decode())

    # update hardware id of the device, so the authentication works
    c8y = c8y_client.client(uuid)
    c8y.publish("s/us", f"110,{uuid},SERVICE CHECK,0.0.2")

    # send signed messages
    for n in range(1, 2):
        timestamp = datetime.utcnow()
        message = "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat())

        c8y.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
        msg = proto.message_signed(uuid, 0x00, hashlib.sha512(message.encode()).digest())
        MESSAGES.append(msg)
        time.sleep(1)
    # send chained messages
    # for n in range(6, 11):
    #     timestamp = datetime.utcnow()
    #     message = "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat())
    #     c8y.publish("s/us", message)
    #     msg = proto.message_chained(testDeviceUUID['Ed25519'], 0x00, hashlib.sha512(message.encode()).digest())
    #     MESSAGES.append(msg)
    #     time.sleep(1)

    ERRORS = 0
    # send out prepared messages
    for n, msg in enumerate(MESSAGES):
        r = requests.post(f"https://niomon.{UBIRCH_ENV}.ubirch.com/", data=msg, auth=tuple(c8y.auth.split(":")))
        if r.status_code == requests.codes.OK:
            try:
                logger.info(f"OK  {n:02d} {repr(proto.message_verify(r.content))}")
            except Exception as e:
                logger.error(f"ERR #{n:03d} verification failed: {binascii.hexlify(r.content).decode()}")
                logger.error(f"ERR ===> {repr(r.content)}")
        else:
            logger.error(f"ERR #{n:03d} {binascii.hexlify(msg).decode()}")
            logger.error(f"HTTP {r.status_code:03d} {r.content}")
            ERRORS += 1

    r = api.deregister_identity(str.encode(json.dumps({
        "publicKey": bytes.decode(base64.b64encode(proto.get_vk())),
        "signature": bytes.decode(base64.b64encode(proto.sk.sign(proto.get_vk())))
    })))
    if r.status_code == requests.codes.ok:
        logger.error("OK  de-register key")
    else:
        logger.error(f"ERR de-register key failed: '{r.content}'")
        ERRORS +=1

    return ERRORS


# errors = run_tests(api, protocol, DEVICE_UUID, TEST_KEY_EDDSA, "ECC_ED25519")
# if errors > 0:
#     logger.error(f"EDDSA ERRORS: {errors}")
#     exit(-1)

errors = run_tests(api, protocol, DEVICE_UUID, TEST_KEY_ECDSA, "ecdsa-p256v1")
if errors > 0:
    logger.error(f"EDDSA ERRORS: {errors}")
    exit(-1)

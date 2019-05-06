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

TEST_UUID = os.getenv("TEST_UUID")
TEST_KEY_EDDSA = os.getenv("TEST_KEY_EDDSA")
TEST_KEY_ECDSA = os.getenv("TEST_KEY_ECDSA")
NEO4J_URL = os.getenv("NEO4J_URL")
NEO4J_AUTH = os.getenv("NEO4J_AUTH")
C8Y_CLIENT_AUTH = os.getenv("C8Y_CLIENT_AUTH")


logger.debug("NEOJ4_URL       = '{}'".format(NEO4J_URL))
logger.debug("NEOJ4_AUTH      = '{}'".format(NEO4J_AUTH))
logger.debug("TEST_UUID       = '{}'".format(TEST_UUID))
logger.debug("TEST_KEY_EDDSA  = '{}'".format(TEST_KEY_EDDSA))
logger.debug("TEST_KEY_ECDSA  = '{}'".format(TEST_KEY_ECDSA))
logger.debug("C8Y_CLIENT_AUTH = '{}'".format(C8Y_CLIENT_AUTH))

SERVER_EDDSA_KEY = "a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66"

class Proto(ubirch.Protocol, ABC):
    __vk = {}
    __sk = {}

    def __init__(self, uuid_eddsa: UUID, uuid_ecdsa: UUID or None) -> None:
        super().__init__()
        self.__vk_server = ed25519.VerifyingKey(SERVER_EDDSA_KEY, encoding='hex')
        self.__vk[uuid_eddsa] = ed25519.VerifyingKey(TEST_KEY_EDDSA[64:].encode(), encoding='hex')
        self.__sk[uuid_eddsa] = ed25519.SigningKey(TEST_EDDSA_KEY.encode(), encoding='hex')
        self.__vk[uuid_ecdsa] = ecdsa.VerifyingKey.from_string(TEST_ECDSA_KEY[])

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__sk[uuid].sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__vk_server.verify(signature, message)

    def get_certificate(self, uuid: UUID) -> dict or None:
        if not uuid in self.__vk:
            return None

        vk = self.__vk[uuid]
        timestamp = int(datetime.utcnow().timestamp())
        created = datetime.fromtimestamp(timestamp)
        not_before = datetime.fromtimestamp(timestamp)
        # TODO fix handling of key validity
        not_after = created + timedelta(days=365)
        return {
            "algorithm": 'ECC_ED25519',
            "created": int(created.timestamp()),
            "hwDeviceId": uuid.bytes,
            "pubKey": vk.to_bytes(),
            "pubKeyId": vk.to_bytes(),
            "validNotAfter": int(not_after.timestamp()),
            "validNotBefore": int(not_before.timestamp())
        }

# test UUID
randomTestUUID = None
testDeviceUUID = {
    'Ed25519': None,
    'ECDSA': None
}
uuidFileName, ext = os.path.splitext(__file__)
try:
    with open(uuidFileName + ".uuid", "r") as f:
        randomTestUUID = f.read()
except IOError:
    BASE_UBIRCH_TEST = UUID("22222222-0000-0000-0000-000000000000")
    randomTestUUID = uuid5(BASE_UBIRCH_TEST, str(secrets.token_bytes(10)))
    with open(uuidFileName + ".uuid", "w") as f:
        f.write(str(randomTestUUID))
finally:
    if TEST_UUID:
        testDeviceUUID['Ed25519'] = UUID(hex=TEST_UUID)
    else:
        testDeviceUUID['Ed25519'] = UUID(str(randomTestUUID))
    testDeviceUUID['ECDSA'] = uuid5(testDeviceUUID['Ed25519'], "ECDSA")

logger.info("** UUID (Ed25519): {}".format(testDeviceUUID['Ed25519']))
logger.info("** UUID (ECDSA)  : {}".format(testDeviceUUID['ECDSA']))

c8y_client = c8y_client.client(testDeviceUUID['Ed25519'], C8Y_CLIENT_AUTH)

api = API(auth=os.getenv("UBIRCH_AUTH"), env='dev', debug=True)
proto = Proto(testDeviceUUID['Ed25519'], testDeviceUUID['ECDSA'])

MESSAGES = []

msg = proto.message_signed(testDeviceUUID['Ed25519'], UBIRCH_PROTOCOL_TYPE_REG,
                           proto.get_certificate(testDeviceUUID['Ed25519']))
if not api.is_identity_registered(testDeviceUUID['Ed25519']):
    pubKeyInfo = proto.get_certificate(testDeviceUUID['Ed25519'])
    # create a json key registration request
    pubKeyInfo['hwDeviceId'] = str(testDeviceUUID['Ed25519'])
    pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
    pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
    pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat() + ".000Z")
    pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat() + ".000Z")
    pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat() + ".000Z")
    signed_message = proto._sign(testDeviceUUID['Ed25519'], json.dumps(pubKeyInfo, separators=(',', ':')).encode())
    signature = base64.b64encode(signed_message).decode()
    pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
    pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
    logger.info(pubKeyRegMsgJson)
    logger.info(api.register_identity(pubKeyRegMsgJson).content.decode())

c8y_client.publish("s/us", f"110,{testDeviceUUID['Ed25519']}, ,0.0.2")

# send signed messages
for n in range(1, 2):
    timestamp = datetime.utcnow()
    message = "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat())

    c8y_client.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
    msg = proto.message_signed(testDeviceUUID['Ed25519'], 0x00, hashlib.sha512(message.encode()).digest())
    MESSAGES.append(msg)
    time.sleep(1)
# send chained messages
# for n in range(6, 11):
#     timestamp = datetime.utcnow()
#     message = "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat())
#     c8y_client.publish("s/us", message)
#     msg = proto.message_chained(testDeviceUUID['Ed25519'], 0x00, hashlib.sha512(message.encode()).digest())
#     MESSAGES.append(msg)
#     time.sleep(1)

ERRORS = 0
# send out prepared messages
for n, msg in enumerate(MESSAGES):
    r = requests.post("https://niomon.dev.ubirch.com/", data=msg, auth=tuple(c8y_client.auth.split(":")))
    if r.status_code == requests.codes.OK:
        try:
            logger.info("OK  {:02d} {}".format(n, repr(proto.message_verify(r.content))))
        except Exception as e:
            logger.error("ERR #{:03d} verification failed: {}".format(n, binascii.hexlify(r.content).decode()))
            logger.error("ERR ===> {}".format(repr(r.content)))
    else:
        logger.error("ERR #{:03d} {}".format(n, binascii.hexlify(msg).decode()))
        logger.error("HTTP {:03d} {}".format(r.status_code, r.content))
        ERRORS += 1

if ERRORS > 0:
    # nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_ERROR,
    #        "{} messages missing, total {} errors\n{}".format(len(MESSAGES_SENT), ERRORS, "\n".join(ERROR_RESULTS)))
    logger.error("TOTAL ERRORS: {}".format(ERRORS))
    exit(-1)

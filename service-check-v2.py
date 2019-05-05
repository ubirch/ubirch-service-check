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
import json
import logging
import os
import secrets
import time
from abc import ABC
from datetime import datetime
from uuid import UUID, uuid5

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
TEST_KEYS = os.getenv("TEST_KEYS")
NEO4J_URL = os.getenv("NEO4J_URL")
NEO4J_AUTH = os.getenv("NEO4J_AUTH")
C8Y_CLIENT_AUTH = os.getenv("C8Y_CLIENT_AUTH")


logger.debug("NEOJ4_URL       = '{}'".format(NEO4J_URL))
logger.debug("NEOJ4_AUTH      = '{}'".format(NEO4J_AUTH))
logger.debug("TEST_UUID       = '{}'".format(TEST_UUID))
logger.debug("TEST_KEYS       = '{}'".format(TEST_KEYS))
logger.debug("C8Y_CLIENT_AUTH = '{}'".format(C8Y_CLIENT_AUTH))


class Proto(ubirch.Protocol, ABC):

    @staticmethod
    def check_key(uuid: UUID) -> dict or None:
        if not (NEO4J_URL and NEO4J_AUTH):
            return
        check_response = requests.get(NEO4J_URL, json={"statements": [{
            "statement": "MATCH (n:PublicKey) WHERE n.infoHwDeviceId='{}' RETURN n;".format(str(uuid)),
        }]}, auth=tuple(NEO4J_AUTH.split(":")))
        try:
            errors = check_response.json()["errors"]
            if len(errors):
                logger.error("Neo4J: errors while checking test UUID: {}: {}"
                             .format(check_response.status_code, errors))
            else:
                logger.info("Neo4J: no errors checking test UUIDs: {}: {}"
                            .format(check_response.status_code, check_response.json()))
            check_response.json()
        except Exception as e:
            logger.error(bytes.decode(check_response.content), e)

    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self.__ks = key_store
        if TEST_KEYS and TEST_UUID:
            try:
                self.__ks.insert_ed25519_keypair(UUID(hex=TEST_UUID),
                                                 ed25519.VerifyingKey(TEST_KEYS[64:].encode(), encoding='hex'),
                                                 ed25519.SigningKey(TEST_KEYS.encode(), encoding='hex'))
            except Exception as e:
                logger.error(e)
                pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


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

# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')
try:
    keystore.find_signing_key(testDeviceUUID['Ed25519'])
    keystore.create_ed25519_keypair(testDeviceUUID['Ed25519'])
except:
    pass

api = API(auth=os.getenv("UBIRCH_AUTH"), env='dev', debug=True)
proto = Proto(keystore)
# proto.check_key(testDeviceUUID['Ed25519'])

if not keystore.exists_signing_key(testDeviceUUID['Ed25519']):
    keystore.create_ed25519_keypair(testDeviceUUID['Ed25519'])


sk = keystore.find_signing_key(testDeviceUUID['Ed25519'])
vk = keystore.find_verifying_key(testDeviceUUID['Ed25519'])

MESSAGES = []

msg = proto.message_signed(testDeviceUUID['Ed25519'], UBIRCH_PROTOCOL_TYPE_REG,
                           keystore.get_certificate(testDeviceUUID['Ed25519']))
if not api.is_identity_registered(testDeviceUUID['Ed25519']):
    pubKeyInfo = keystore.get_certificate(testDeviceUUID['Ed25519'])
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
for n in range(1, 10):
    timestamp = datetime.utcnow()
    c8y_client.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
    msg = proto.message_signed(testDeviceUUID['Ed25519'], 0x53, {'ts': int(timestamp.timestamp()), 'v': n})
    MESSAGES.append(msg)
    time.sleep(1)
# send chained messages
for n in range(6, 11):
    timestamp = datetime.utcnow()
    c8y_client.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
    msg = proto.message_chained(testDeviceUUID['Ed25519'], 0x53, {'ts': int(timestamp.timestamp()), 'v': n})
    MESSAGES.append(msg)
    time.sleep(1)

ERRORS = 0
# send out prepared messages
for n, msg in enumerate(MESSAGES):
    r = requests.post("https://niomon.dev.ubirch.com", data=msg, auth=tuple(c8y_client.auth.split(":")))
    if r.status_code == requests.codes.OK:
        try:
            logger.info("OK  {:02d} {}".format(n, repr(proto.message_verify(r.content))))
        except Exception as e:
            logger.error("ERR verification failed: {}".format(repr(r.content)))
    else:
        logger.error("ERR #{:03d} {}".format(n, binascii.hexlify(msg)))
        logger.error("HTTP {:03d} {}".format(r.status_code, r.content))
        ERRORS += 1

if ERRORS > 0:
    # nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_ERROR,
    #        "{} messages missing, total {} errors\n{}".format(len(MESSAGES_SENT), ERRORS, "\n".join(ERROR_RESULTS)))
    logger.error("TOTAL ERRORS: {}".format(ERRORS))
    exit(-1)

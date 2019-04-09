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

import requests
import ubirch
from ubirch import API
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

import c8y_client

LOGLEVEL = os.getenv("LOGLEVEL", "DEBUG").upper()
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=LOGLEVEL)
logger = logging.getLogger()

ERRORS = 0

NEO4J_URL = os.getenv("NEO4J_URL")
NEO4J_AUTH = os.getenv("NEO4J_AUTH")

logger.debug("NEOJ4_URL     = '{}'".format(NEO4J_URL))
logger.debug("NEOJ4_AUTH    = '{}'".format(NEO4J_AUTH))


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

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


# test UUID
randomTestUUID = None
testDeviceUUID = None
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
    testDeviceUUID = UUID(hex=os.getenv('UBIRCH_DEVICE_UUID', str(randomTestUUID)))

logger.info("** UUID: {}".format(testDeviceUUID))

c8y_client = c8y_client.client(testDeviceUUID)

# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')
try:
    keystore.find_signing_key(testDeviceUUID)
    keystore.create_ed25519_keypair(testDeviceUUID)
except:
    pass

api = API(auth=os.getenv("UBIRCH_AUTH"), env='dev', debug=True)
proto = Proto(keystore)
proto.check_key(testDeviceUUID)

if not keystore.exists_signing_key(testDeviceUUID):
    keystore.create_ed25519_keypair(testDeviceUUID)

sk = keystore.find_signing_key(testDeviceUUID)
vk = keystore.find_verifying_key(testDeviceUUID)

MESSAGES = []

msg = proto.message_signed(testDeviceUUID, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(testDeviceUUID))
if not api.is_identity_registered(testDeviceUUID):
    pubKeyInfo = keystore.get_certificate(testDeviceUUID)
    # create a json key registration request
    pubKeyInfo['hwDeviceId'] = str(testDeviceUUID)
    pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
    pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
    pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat() + ".000Z")
    pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat() + ".000Z")
    pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat() + ".000Z")
    signed_message = proto._sign(testDeviceUUID, json.dumps(pubKeyInfo, separators=(',', ':')).encode())
    signature = base64.b64encode(signed_message).decode()
    pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
    pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
    logger.info(pubKeyRegMsgJson)
    logger.info(api.register_identity(pubKeyRegMsgJson).content.decode())

# send the message the normal way as soon as the register service is in place
# MESSAGES.append(msg)

# send signed messages
for n in range(1, 10):
    timestamp = datetime.utcnow()
    c8y_client.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
    msg = proto.message_signed(testDeviceUUID, 0x53, {'ts': int(timestamp.timestamp()), 'v': n})
    MESSAGES.append(msg)
    time.sleep(1)
# send chained messages
for n in range(6, 11):
    timestamp = datetime.utcnow()
    c8y_client.publish("s/us", "200,customValue,custom,{},X,{}".format(n, timestamp.isoformat()))
    msg = proto.message_chained(testDeviceUUID, 0x53, {'ts': int(timestamp.timestamp()), 'v': n})
    MESSAGES.append(msg)
    time.sleep(1)

# send out prepared messages
for n, msg in enumerate(MESSAGES):
    r = requests.post("https://niomon.dev.ubirch.com", data=msg, auth=tuple(c8y_client.auth.split(":")))
    if r.status_code == requests.codes.OK:
        logger.info("OK  {:02d} {}".format(n, binascii.hexlify(msg)))
    else:
        logger.error("ERR #{:03d} {}".format(n, binascii.hexlify(msg)))
        logger.error("HTTP {:03d} {}".format(r.status_code, r.content))

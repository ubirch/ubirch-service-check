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
from datetime import datetime
from uuid import UUID

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

class Proto(ubirch.Protocol):

    @staticmethod
    def check_key(uuid: UUID) -> dict or None:
        if not (NEO4J_URL and NEO4J_AUTH): return
        r = requests.get(NEO4J_URL, json={"statements": [{
            "statement": "MATCH (n:PublicKey) WHERE n.infoHwDeviceId='{}' RETURN n;".format(str(uuid)),
        }]}, auth=tuple(NEO4J_AUTH.split(":")))
        try:
            errors = r.json()["errors"]
            if len(errors):
                logger.error("Neo4J: errors while checking test UUID: {}: {}".format(r.status_code, errors))
            else:
                logger.info("Neo4J: no errors checking test UUIDs: {}: {}".format(r.status_code, r.json()))
            r.json()
        except Exception as e:
            logger.error(bytes.decode(r.content), e)

    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self.__ks = key_store

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


# test UUID
rnduuid = binascii.hexlify(secrets.token_bytes(6)).decode()
uuid = UUID(hex=os.getenv('UBIRCH_DEVICE_UUID', "22222222-0000-0000-0000-{}".format()))

c8y_client = c8y_client.client(uuid)

# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')
try:
    keystore.find_signing_key(uuid)
    keystore.create_ed25519_keypair(uuid)
except:
    pass

api = API(auth=os.getenv("UBIRCH_AUTH"), env='dev', debug = True)
proto = Proto(keystore)
proto.check_key(uuid)

if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

sk = keystore.find_signing_key(uuid)
vk = keystore.find_verifying_key(uuid)

MESSAGES = []

msg = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
if not api.is_identity_registered(uuid):
    pubKeyInfo = keystore.get_certificate(uuid)
    # create a json key registration request
    pubKeyInfo['hwDeviceId'] = str(uuid)
    pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
    pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
    pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat()+".000Z")
    pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat()+".000Z")
    pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat()+".000Z")
    signature = base64.b64encode(proto._sign(uuid, json.dumps(pubKeyInfo, separators=(',', ':')).encode())).decode()
    pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
    pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
    logger.info(pubKeyRegMsgJson)
    logger.info(api.register_identity(pubKeyRegMsgJson).content.decode())

# send the message the normal way as soon as the register service is in place
#MESSAGES.append(msg)

# send signed messages
for n in range(1, 10):
    msg = proto.message_signed(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES.append(msg)
# send chained messages
for n in range(6, 11):
    msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES.append(msg)

# send out prepared messages
for n, msg in enumerate(MESSAGES):
    r = requests.post("https://niomon.dev.ubirch.com", data=msg, auth=tuple(c8y_client.auth.split(":")))
    if r.status_code == requests.codes.OK:
        logger.info("OK  {:02d} {}".format(n, binascii.hexlify(msg)))
    else:
        logger.error("ERR #{:03d} {}".format(n, binascii.hexlify(msg)))
        logger.error("HTTP {:03d} {}".format(r.status_code, r.content))

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
import binascii
import logging
import os
from datetime import datetime
from uuid import UUID

import requests
import ubirch
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
uuid = UUID(hex=os.getenv('UBIRCH_DEVICE_UUID', "22222222-0000-0000-0000-000000000000"))

c8y_client = c8y_client.client(uuid)

# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')
try:
    keystore.find_signing_key(uuid)
    keystore.create_ed25519_keypair(uuid)
except:
    pass

proto = Proto(keystore)
proto.check_key(uuid)

if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

sk = keystore.find_signing_key(uuid)
vk = keystore.find_verifying_key(uuid)

MESSAGES = []

# msg = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
# MESSAGES.append(msg)

# send signed messages
for n in range(1, 10):
    msg = proto.message_signed(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES.append(msg)
# send chained messages
for n in range(6, 11):
    msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES.append(msg)

# send out prepared messages
for n, msg in enumerate(MESSAGES[:1]):
    r = requests.post("https://niomon.dev.ubirch.com", data=msg, auth=tuple(c8y_client.auth.split(":")))
    if r.status_code == requests.codes.OK:
        logger.info("OK  {:02d} {}".format(n, binascii.hexlify(msg)))
    else:
        logger.error("ERR #{:03d} {}".format(n, binascii.hexlify(msg)))
        logger.error("HTTP {:03d} {}".format(r.status_code, r.content))

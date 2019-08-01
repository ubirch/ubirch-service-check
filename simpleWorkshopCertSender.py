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
import random
import uuid
from abc import ABC
from datetime import datetime, timedelta
from uuid import UUID

import ecdsa as ecdsa
import ed25519
import requests
import ubirch
from ubirch import API

LOGLEVEL = os.getenv("LOGLEVEL", "DEBUG").upper()
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=LOGLEVEL)
logger = logging.getLogger()
# change this if you want requests log messages
logging.getLogger("urllib3").setLevel(logging.WARNING)

ERRORS = 0

UBIRCH_ENV = os.getenv("UBIRCH_ENV", "dev")
UBIRCH_AUTH = os.getenv("UBIRCH_AUTH")

logger.debug(f"UBIRCH_ENV      = '{UBIRCH_ENV}'")
logger.debug(f"UBIRCH_AUTH     = '{UBIRCH_AUTH}'")


# == ubirch protocol implementation =====================================================
class Proto(ubirch.Protocol, ABC):

    def __init__(self, uuid: UUID) -> None:
        super().__init__()

        self.sk = None
        self.vk = None
        self.type = None
        self.uuid = None

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

    def _hash(self, message: bytes) -> bytes:
        if self.type == 'ECC_ED25519':
            return ubirch.Protocol._hash(self, message)
        else:
            return message

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.sk.sign(message)

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
# uuid = UUID(hex="da3ffc56-a7a7-552a-a3fa-a92ef0607451")
uuid = UUID(hex="e97e160c-6117-5b89-ac98-15aeb52655e0")
auth = UBIRCH_AUTH

logger.info(f"** UUID: {uuid}")

keystore = ubirch.KeyStore(
    "/Volumes/Keybase (dermicha)/team/ubirchkeys/UBIRCHKEYS/ubirch/workshop_certs/workshop_certs.jks", 'service-check')
key = keystore.find_signing_key(uuid)

# logger.debug("{}".format(binascii.hexlify(key.to_bytes()).decode()))

api = API(auth=auth, env=UBIRCH_ENV, debug=(LOGLEVEL == 'DEBUG'))
protocol = Proto(uuid=uuid)
protocol.update_key(uuid, binascii.hexlify(key.to_bytes()).decode(), "ECC_ED25519")

# pubKeyInfo = protocol.get_certificate()
# # create a json key registration request
# pubKeyInfo['hwDeviceId'] = str(uuid)
# pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
# pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
# pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat() + ".000Z")
# pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat() + ".000Z")
# pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat() + ".000Z")
#
# signable_json = json.dumps(pubKeyInfo, separators=(',', ':')).encode()
# # logger.info(signable_json.decode())
# signed_message = protocol._sign(uuid, signable_json)
# signature = base64.b64encode(signed_message).decode()
# pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
# pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
# logger.info(f"=== registering public key: {api.register_identity(pubKeyRegMsgJson).content.decode()}")

timestamp = datetime.utcnow()
created = "21.02.2019"
name = "Thorsten Schmitz"
workshop = "Workshop IoT & Blockchain"
message = "{{\"created\":\"{0}\",\"name\":\"{1}\",\"workshop\":\"{2}\"}}".format(created, name, workshop)
digest = hashlib.sha512(message.encode()).digest()
logger.info("current hash: {0}".format(binascii.b2a_base64(digest)))
msg = protocol.message_signed(uuid=uuid, type=0x00, payload=digest)
r = requests.post(f"https://niomon.{UBIRCH_ENV}.ubirch.com/",
                  headers={"X-Niomon-Purge-Caches": "true"},
                  timeout=5,
                  data=msg, auth=tuple(auth.split(":")))
logger.info("response status: {}".format(r.status_code))

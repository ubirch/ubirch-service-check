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
import time
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

ICINGA_URL = os.getenv("ICINGA_URL")
ICINGA_AUTH = os.getenv("ICINGA_AUTH")
UBIRCH_ENV = os.getenv("UBIRCH_ENV", "dev")
UBIRCH_AUTH = os.getenv("UBIRCH_AUTH")
TEST_UUID = os.getenv("TEST_UUID")
TEST_KEY_EDDSA = os.getenv("TEST_KEY_EDDSA")
TEST_KEY_ECDSA = os.getenv("TEST_KEY_ECDSA")
SRVR_KEY_EDDSA = os.getenv("SRVR_KEY_EDDSA", "a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66")
SRVR_KEY_ECDSA = os.getenv("SRVR_KEY_ECDSA")

logger.debug(f"ICINGA_URL      = '{ICINGA_URL}'")
logger.debug(f"ICINGA_AUTH     = '{ICINGA_AUTH}'")
logger.debug(f"UBIRCH_ENV      = '{UBIRCH_ENV}'")
logger.debug(f"UBIRCH_AUTH     = '{UBIRCH_AUTH}'")
logger.debug(f"TEST_UUID       = '{TEST_UUID}'")
logger.debug(f"SRVR_KEY_EDDSA  = '{SRVR_KEY_EDDSA}'")
logger.debug(f"SRVR_KEY_ECDSA  = '{SRVR_KEY_ECDSA}'")
logger.debug(f"TEST_KEY_EDDSA  = '{TEST_KEY_EDDSA}'")
logger.debug(f"TEST_KEY_ECDSA  = '{TEST_KEY_ECDSA}'")

# == NAGIOS / ICINGA SETTINGS ==========================================================
NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_ERROR = 2
NAGIOS_UNKNOWN = 3


def nagios(client, env, service, code, message="OK"):
    if not client: client = "ubirch"
    if not env: env = "local"
    env = client + "." + env

    data = {
        "exit_status": code,
        "plugin_output": message,
        "check_source": env,
        "ttl": 3600.0
    }

    if code == NAGIOS_OK:
        logger.info("{}.ubirch.com {} {}".format(env, service, message))
    elif code == NAGIOS_WARNING:
        logger.warning("{}.ubirch.com {} {}".format( env, service, message))
    else:
        logger.error("{}.ubirch.com {} {}".format(env, service, message))

    if ICINGA_URL and ICINGA_AUTH:
        r = requests.post(ICINGA_URL + "?" + "service={}.ubirch.com!{}".format(env, service),
                          json=data, headers={"Accept": "application/json"}, auth=tuple(ICINGA_AUTH.split(":")))
        if r.status_code != 200:
            logger.error("ERROR: {}: {}".format(r.status_code, bytes.decode(r.content)))
        else:
            logger.debug("{}: {}".format(r.status_code, bytes.decode(r.content)))


# == ubirch protocol implementation =====================================================
class Proto(ubirch.Protocol, ABC):
    SERVER_EDDSA_KEY = SRVR_KEY_EDDSA or None
    SERVER_ECDSA_KEY = SRVR_KEY_ECDSA or None

    def __init__(self, uuid: UUID) -> None:
        super().__init__()
        self.__vk_eddsa = ed25519.VerifyingKey(self.SERVER_EDDSA_KEY, encoding='hex')
        if self.SERVER_ECDSA_KEY is not None:
            self.__vk_ecdsa = ecdsa.VerifyingKey.from_string(binascii.unhexlify(self.SERVER_ECDSA_KEY),
                                                                                curve=ecdsa.curves.NIST256p,
                                                                                hashfunc=hashlib.sha256)
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

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        if self.type == 'ECC_ED25519':
            return self.__vk_eddsa.verify(signature, message)
        else:
            # TODO fix this as soon as the server can create different signatures
            return self.__vk_eddsa.verify(signature, ubirch.Protocol._hash(self, message))

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


def run_tests(api, proto, uuid, auth, key, type) -> int:
    MESSAGES = []

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
        # logger.info(signable_json.decode())
        signed_message = proto._sign(uuid, signable_json)
        signature = base64.b64encode(signed_message).decode()
        pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
        pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()
        logger.info(f"=== registering public key: {api.register_identity(pubKeyRegMsgJson).content.decode()}")

    # send 5 signed and 5 chained messages
    for n in range(1, 11):
        timestamp = datetime.utcnow()
        message = "{},{}".format(n, timestamp.isoformat())
        if n < 6:
            msg = proto.message_signed(uuid, 0x00, hashlib.sha512(message.encode()).digest())
        else:
            msg = proto.message_chained(uuid, 0x00, hashlib.sha512(message.encode()).digest())
        MESSAGES.append(msg)
        time.sleep(1)

    ERRORS = 0
    # send out prepared messages
    for n, msg in enumerate(MESSAGES):
        r = requests.post(f"https://niomon.{UBIRCH_ENV}.ubirch.com/",
                          headers={"X-Niomon-Purge-Caches": "true"},
                          data=msg, auth=tuple(auth.split(":")))
        if r.status_code == requests.codes.OK:
            try:
                logger.info(f"=== OK  #{n:03d} {repr(proto.message_verify(r.content))}")
            except Exception as e:
                logger.error(f"!!! ERR #{n:03d} verification failed: {binascii.hexlify(r.content).decode()}")
                logger.error(f"!!! ERR ===> {repr(r.content)}")
        else:
            logger.error(f"!!! ERR #{n:03d} {binascii.hexlify(msg).decode()}")
            logger.error(f"!!! HTTP {r.status_code:03d} {binascii.hexlify(r.content).decode()}")
            try:
                logger.error(f"!!! RSP #{n:03d} {proto.message_verify(r.content)}")
            except Exception as e:
                logger.error(f"!!! can't decode and verify response: {e.args}")
                pass
            ERRORS += 1

    r = api.deregister_identity(str.encode(json.dumps({
        "publicKey": bytes.decode(base64.b64encode(proto.get_vk())),
        "signature": bytes.decode(base64.b64encode(proto.sk.sign(proto.get_vk())))
    })))
    logger.info(f"=== de-registering public key: {r.content.decode()}")
    if r.status_code == requests.codes.ok:
        logger.info("=== OK  de-register key")
    else:
        logger.error(f"!!! ERR de-register key failed: '{r.content}'")
        ERRORS +=1

    return ERRORS


# Device Test UUID
DEVICE_UUID = UUID(hex="FFFF160c-6117-5b89-ac98-15aeb52655e0")
logger.info(f"** UUID: {DEVICE_UUID}")

api = API(auth=UBIRCH_AUTH, env=UBIRCH_ENV, debug=(LOGLEVEL == 'DEBUG'))
protocol = Proto(DEVICE_UUID)

logger.info("== EDDSA ==================================================")
errors = run_tests(api, protocol, DEVICE_UUID, UBIRCH_AUTH, TEST_KEY_EDDSA, "ECC_ED25519")
if errors > 0:
    logger.error(f"EDDSA ERRORS: {errors}")
    nagios(None, UBIRCH_ENV, "ED25519", NAGIOS_ERROR, f"{errors} checks failed")
else:
    nagios(None, UBIRCH_ENV, "ED25519", NAGIOS_OK, f"all checks successful")

logger.info("== ECDSA ==================================================")
errors = run_tests(api, protocol, DEVICE_UUID, UBIRCH_AUTH, TEST_KEY_ECDSA, "ecdsa-p256v1")
if errors > 0:
    logger.error(f"ECDSA ERRORS: {errors}")
    nagios(None, UBIRCH_ENV, "ECDSA", NAGIOS_ERROR, f"{errors} checks failed")
else:
    nagios(None, UBIRCH_ENV, "ECDSA", NAGIOS_OK, f"all checks successful")

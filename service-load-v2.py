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
import concurrent
import sys
import time
from concurrent.futures import ThreadPoolExecutor
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
import timer as timer
import ubirch
from ubirch import API

LOGLEVEL = os.getenv("LOGLEVEL", "INFO").upper()
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=LOGLEVEL)
logger = logging.getLogger()
# change this if you want requests log messages
logging.getLogger("urllib3").setLevel(logging.WARNING)

ERRORS = 0

UBIRCH_ENV = os.getenv("UBIRCH_ENV", "dev")
UBIRCH_AUTH = os.getenv("UBIRCH_AUTH")
TEST_UUID = os.getenv("TEST_UUID")
TEST_KEY_EDDSA = os.getenv("TEST_KEY_EDDSA")
TEST_KEY_ECDSA = os.getenv("TEST_KEY_ECDSA")
SRVR_KEY_EDDSA = os.getenv("SRVR_KEY_EDDSA")
SRVR_KEY_ECDSA = os.getenv("SRVR_KEY_ECDSA")

if not TEST_UUID or TEST_UUID == '':
    TEST_UUID = "aaaa160c-6117-5b89-ac98-15aeb52655e0"

if not SRVR_KEY_EDDSA or SRVR_KEY_EDDSA == '':
    SRVR_KEY_EDDSA = "a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66"

logger.debug(f"UBIRCH_ENV      = '{UBIRCH_ENV}'")
logger.debug(f"UBIRCH_AUTH     = '{UBIRCH_AUTH}'")
logger.debug(f"TEST_UUID       = '{TEST_UUID}'")
logger.debug(f"SRVR_KEY_EDDSA  = '{SRVR_KEY_EDDSA}'")
logger.debug(f"SRVR_KEY_ECDSA  = '{SRVR_KEY_ECDSA}'")
logger.debug(f"TEST_KEY_EDDSA  = '{TEST_KEY_EDDSA}'")
logger.debug(f"TEST_KEY_ECDSA  = '{TEST_KEY_ECDSA}'")

if not TEST_KEY_EDDSA or TEST_KEY_EDDSA == '':
    logger.error("MISSING EDDSA KEY")
    exit(-1)
if not TEST_KEY_ECDSA or TEST_KEY_ECDSA == '':
    logger.error("MISSING ECDSA KEY")
    exit(-1)


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



def run_tests(api, proto, uuid, auth, key, type, count) -> (int, int, int):
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

    logger.info(f"=== generating {count} messages")
    # send 5 signed and 5 chained messages
    for n in range(1, count + 1):
        timestamp = datetime.utcnow()
        message = f"{n},{timestamp.isoformat()},{random.random()*1e9}"
        digest = hashlib.sha512(message.encode()).digest()
        msg = proto.message_signed(uuid, 0x00, digest)
        MESSAGES.append([msg, digest])
    logger.info(f"=== done")


    def post(auth, msg, n, timeout):
        error_send = 0
        error_vrfy = 0
        if n % 200 == 0:
            sys.stdout.write(f"\n {n:06d} ")
        try:
            r = requests.post(f"https://niomon.{UBIRCH_ENV}.ubirch.com/",
                              # headers={"X-Niomon-Purge-Caches": "true"},
                              timeout=timeout,
                              data=bytes(msg[0]), auth=tuple(auth.split(":")))

            if r.status_code == requests.codes.OK:
                sys.stderr.write(".")
                # try:
                #     logger.info(f"=== OK  #{n:03d} {repr(proto.message_verify(r.content))}")
                # except Exception:
                #     logger.error(f"!!! ERR #{n:03d} response verification failed: {binascii.hexlify(r.content).decode()}")
                #     logger.error(f"!!! ERR ===> {repr(r.content)}")
                #     error_send = True
            else:
                sys.stderr.write(f"!{r.status_code}")
                # logger.error(f"!!! ERR #{n:03d} {binascii.hexlify(msg[0]).decode()}")
                # logger.error(f"!!! HTTP {r.status_code:03d} {binascii.hexlify(r.content).decode()}")
                # try:
                #     logger.error(f"!!! RSP #{n:03d} {proto.message_verify(r.content)}")
                # except Exception as e:
                #     logger.error(f"!!! can't decode and verify response: {e.args}")
                error_send=True
        except Exception as e:
            sys.stdout.write("T")
            # logger.error(f"!!! ERR #{n:03d} request timeout sending message: {e.args}", e)
            error_send = True

        # try:
        #     time.sleep(5)
        #     r = requests.post(f"https://verify.{UBIRCH_ENV}.ubirch.com/api/verify",
        #                       headers={"Accept": "application/json", "Content-Type": "text/plain"},
        #                       timeout=timeout,
        #                       data=base64.b64encode(msg[1]))
        #     if r.status_code == requests.codes.ok:
        #         if json.loads(r.content)["seal"] == base64.b64encode(msg[0]).decode():
        #             logger.info(f"=== OK  #{n:03d} verification matches")
        #         else:
        #             logger.error(f"!!! ERR #{n:03d} verification faileds")
        #             error_vrfy = True
        #     else:
        #         logger.error(f"!!! ERR #{n:03d} verification failed: {r.status_code} {r.content.decode()}")
        #         error_vrfy = True
        # except Exception as e:
        #     logger.error(f"!!! ERR #{n:03d} request timeout verifying message: {e.args}")
        #     error_vrfy = True
        return (error_send, error_vrfy)

    errors_gnrl = 0
    errors_send = 0
    errors_vrfy = 0

    start = time.process_time_ns()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(post, auth, msg, i, 30): (i, msg) for (i, msg) in enumerate(MESSAGES)}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                (s, v) = future.result()
                errors_send += s
                errors_vrfy += v
            except Exception as e:
                errors_gnrl += 1
                logger.error("??", e)
    elapsed = (time.process_time_ns() - start)
    sys.stderr.write("\n")
    logger.info(f"{elapsed/1e9:.2f}s / {count / (elapsed / 1e9):.2f} msg/s")

    r = api.deregister_identity(str.encode(json.dumps({
        "publicKey": bytes.decode(base64.b64encode(proto.get_vk())),
        "signature": bytes.decode(base64.b64encode(proto.sk.sign(proto.get_vk())))
    })))
    logger.info(f"=== de-registering public key: {r.content.decode()}")
    if r.status_code == requests.codes.ok:
        logger.info("=== OK  de-register key")
    else:
        logger.error(f"!!! ERR de-register key failed: '{r.content}'")
        errors_gnrl +=1

    return errors_gnrl, errors_send, errors_vrfy


# Device Test UUID
DEVICE_UUID = UUID(hex=TEST_UUID)
logger.info(f"** BASE UUID: {DEVICE_UUID}")

api = API(auth=UBIRCH_AUTH, env=UBIRCH_ENV, debug=(LOGLEVEL == 'DEBUG'))
protocol = Proto(DEVICE_UUID)

has_failed = False

count = 10000

logger.info("== EDDSA ==================================================")
(gen, snd, vrf) = run_tests(api, protocol, uuid.uuid5(DEVICE_UUID, "ED25519"), UBIRCH_AUTH, TEST_KEY_EDDSA, "ECC_ED25519", count)
logger.info(f"ERRORS: general={gen}, send={snd}, verify={vrf}")

# logger.info("== ECDSA ==================================================")
# (gen, snd, vrf) = run_tests(api, protocol, uuid.uuid5(DEVICE_UUID, "ECDSA"), UBIRCH_AUTH, TEST_KEY_ECDSA, "ecdsa-p256v1", count)
# logger.info(f"ERROS: general={gen}, send={snd}, verify={vrf}")

if has_failed:
    exit(-1)
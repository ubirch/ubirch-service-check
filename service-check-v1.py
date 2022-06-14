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
import time
from json import JSONDecodeError
from uuid import UUID

from ed25519 import SigningKey, VerifyingKey, BadSignatureError

import requests
import ubirch
from ubirch.ubirch_api import AVATAR_SERVICE, KEY_SERVICE
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

LOGLEVEL = os.getenv("LOGLEVEL", "INFO").upper()
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=LOGLEVEL)
logger = logging.getLogger()

ERRORS = 0

UBIRCH_CLIENT = os.getenv("UBIRCH_CLIENT")
if UBIRCH_CLIENT and not UBIRCH_CLIENT.strip():
    UBIRCH_CLIENT = None

UBIRCH_ENV = os.getenv("UBIRCH_ENV")
UBIRCH_AUTH = os.getenv("UBIRCH_AUTH")

# test UUID
uuid = UUID(hex=os.getenv('UBIRCH_DEVICE_UUID', "00000000-0000-0000-0000-000000000000"))

# private key for signing test messages
sk = SigningKey(binascii.unhexlify(os.getenv('UBIRCH_PRIV_KEY')))
vk = sk.get_verifying_key()

# public key of the ubirch avatar service for verification of responses
avatar_vk = VerifyingKey(binascii.unhexlify(os.getenv('UBIRCH_AVATAR_PUB_KEY')))

logger.debug("UBIRCH_CLIENT           = '{}'".format(UBIRCH_CLIENT))
logger.debug("UBIRCH_ENV              = '{}'".format(UBIRCH_ENV))
logger.debug("UBIRCH_AUTH             = '{}'".format(UBIRCH_AUTH))
logger.debug("UBIRCH_DEVICE_UUID      = '{}'".format(uuid))
logger.debug("UBIRCH_AVATAR_PUB_KEY   = '{}'".format(avatar_vk.to_ascii(encoding="hex")))

NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_ERROR = 2
NAGIOS_UNKNOWN = 3


def nagios(client, env, service, code, message="OK"):
    global ERRORS

    if not client: client = "ubirch"
    if not env: env = "local"
    env = client + "." + env

    if code == NAGIOS_OK:
        logger.info("{}.ubirch.com {} {}".format(env, service, message))
    elif code == NAGIOS_WARNING:
        logger.warning("{}.ubirch.com {} {}".format(env, service, message))
    else:
        logger.error("{}.ubirch.com {} {}".format(env, service, message))


def create_trackle_messages() -> list:
    msgs: list = []

    create_trackle_messages.wakeup_count += 5
    min_val = 3500
    max_val = 4200
    interval_s = 60
    now = int(time.time())

    values = {}

    for i in range(0, 5):
        values["%.10s" % int(now + i * interval_s)] = random.randint(min_val, max_val)

    payload = [
        "v1.0.2-PROD-20180326103205 (v5.6.6)",
        create_trackle_messages.wakeup_count,
        3,  # status: ready
        values,
        {
            'min': min_val,
            'max': max_val,
            'i': interval_s * 1000,
            'il': 1800000,
        }
    ]

    chained = proto.message_chained(uuid, 0x54, payload)
    msgs.append(chained)

    return msgs


create_trackle_messages.wakeup_count = 0


def verify_avatar_response(message: bytes):
    avatar_vk.verify(message[-64:], hashlib.sha512(message[:-67]).digest())


class Proto(ubirch.Protocol):
    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self.__ks = key_store

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    # this is a bad hack to fix the problem of an unpinned msgpack dependency
    def _Protocol__serialize(self, msg: any) -> bytearray:
        import msgpack
        return bytearray(msgpack.packb(msg, use_bin_type=False))


# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')

if not keystore.exists_signing_key(uuid):
    keystore.insert_ed25519_keypair(uuid, vk, sk)

# configure client specific services if we have one instead of core ubirch services
if UBIRCH_CLIENT and UBIRCH_CLIENT.strip():
    # create a sub-class of the ubirch API to use
    class ClientAPI(ubirch.API):
        def __init__(self, client: str, auth: str = None, env: str = None, debug: bool = False) -> None:
            super().__init__(auth, env, debug)
            self._services[AVATAR_SERVICE] = "https://ubirch.api.{}.{}.ubirch.com/api/avatarService/v1" \
                .format(client, env)


    # instantiate the sub class to include ubirch-client
    api = ClientAPI(client=UBIRCH_CLIENT, env=UBIRCH_ENV, auth=UBIRCH_AUTH)
else:
    api = ubirch.API(env=UBIRCH_ENV, auth=UBIRCH_AUTH)

proto = Proto(keystore)

# do an initial deepCheck test
services = [KEY_SERVICE, AVATAR_SERVICE]  # , NOTARY_SERVICE, CHAIN_SERVICE]
for service in services:
    try:
        logger.info("DEEPCHECK: {}".format(api.get_url(service) + "/deepCheck"))
        r = requests.get(api.get_url(service) + "/deepCheck", timeout=1.0)
        try:
            response = r.json()
            if not response['status']:
                ERRORS += 1
                nagios(UBIRCH_CLIENT, UBIRCH_ENV, service + "-deepCheck", NAGIOS_ERROR,
                       "{} {}".format(r.status_code, response['messages']))
            else:
                nagios(UBIRCH_CLIENT, UBIRCH_ENV, service + "-deepCheck", NAGIOS_OK)

        except JSONDecodeError as e:
            ERRORS += 1
            nagios(UBIRCH_CLIENT, UBIRCH_ENV, service + "-deepCheck", NAGIOS_ERROR,
                   "{} {}".format(r.status_code, bytes.decode(r.content).split('\n')[0]))

    except Exception as e:
        ERRORS += 1
        nagios(UBIRCH_CLIENT, UBIRCH_ENV, service + "-deepCheck", NAGIOS_ERROR, str(e))

# check, register and deregister key
try:
    if api.is_identity_registered(uuid):
        # remove any existing key
        r = api.deregister_identity(str.encode(json.dumps({
            "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
            "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
        })))
        if r.status_code != 200:
            nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-deregister", NAGIOS_ERROR,
                   "{} {}".format(r.status_code, bytes.decode(r.content)))
except Exception as e:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-deregister", NAGIOS_ERROR, "{}".format(str(e)))

if api.is_identity_registered(uuid):
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-register", NAGIOS_ERROR,
           "{}".format("public key already registered"))
    exit(-1)

# register key
key_registration = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
r = api.register_identity(key_registration)
if r.status_code == requests.codes.ok:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-register", NAGIOS_OK)
else:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-register", NAGIOS_ERROR,
           "{} {}".format(r.status_code, bytes.decode(r.content)))

MESSAGES_TO_SEND = create_trackle_messages()
ERROR_RESULTS = []

# send out prepared messages
for n, msg in enumerate(MESSAGES_TO_SEND):
    logger.debug("message(#{}): {}".format(n, binascii.hexlify(msg)))
    r = api.send(msg)
    if r.status_code == requests.codes.accepted:
        logger.info("{}.service.{}.message.{}.send: OK".format(UBIRCH_ENV, AVATAR_SERVICE, n))
        MESSAGES_TO_SEND.remove(msg)

        # verify the backend response
        logger.debug("response(#{}): {}".format(n, binascii.hexlify(r.content)))
        try:
            verify_avatar_response(r.content)
            logger.info("{}.service.{}.response.{}.verify: OK".format(UBIRCH_ENV, AVATAR_SERVICE, n))
        except BadSignatureError as e:
            ERRORS += 1
            ERROR_RESULTS.append("{} service response(#{}): {}".format(AVATAR_SERVICE, n, binascii.hexlify(r.content)))
            logger.error("{}.service.{}.response.{}.verify: FAILED: {} (public key: {})"
                         .format(UBIRCH_ENV, AVATAR_SERVICE, n, binascii.hexlify(r.content),
                                 bytes.decode(avatar_vk.to_ascii(encoding="hex"))))

    else:
        ERRORS += 1
        ERROR_RESULTS.append("message(#{}, {}): {}".format(n, r.status_code, bytes.decode(r.content)))
        logger.error("{}.service.{}.message.{}.send: FAILED: {} {}"
                     .format(UBIRCH_ENV, AVATAR_SERVICE, n, r.status_code, bytes.decode(r.content)))

# delete key
r = api.deregister_identity(str.encode(json.dumps({
    "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
    "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
})))
if r.status_code == requests.codes.ok:
    # logger.info("{}.service.{}.deregister_identity: OK".format(UBIRCH_ENV, KEY_SERVICE))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-deregister", NAGIOS_OK)
else:
    ERRORS += 1
    # logger.error("{}.service.{}.deregister_identity: FAILED: {}"
    #              .format(UBIRCH_ENV, KEY_SERVICE, bytes.decode(r.content)))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-deregister", NAGIOS_ERROR,
           "{} {}".format(r.status_code, bytes.decode(r.content)))

if ERRORS > 0:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_ERROR,
           "{} messages not sent, total {} errors\n{}".format(len(MESSAGES_TO_SEND), ERRORS, "\n".join(ERROR_RESULTS)))
    logger.error("{} ERRORS".format(ERRORS))
    exit(-1)
else:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_OK)
    logger.info("All Services: OK")
    exit(0)

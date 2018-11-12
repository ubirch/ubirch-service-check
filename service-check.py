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
import threading
import time
from datetime import datetime
from json import JSONDecodeError
from uuid import UUID

import paho.mqtt.client as mqtt
import requests
import ubirch
from ubirch.ubirch_api import AVATAR_SERVICE, KEY_SERVICE
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()

ERRORS = 0

UBIRCH_CLIENT = os.getenv("UBIRCH_CLIENT")
if UBIRCH_CLIENT is not None and not UBIRCH_CLIENT.strip():
    UBIRCH_CLIENT = None

UBIRCH_ENV = os.getenv("UBIRCH_ENV")
UBIRCH_AUTH = os.getenv("UBIRCH_AUTH")
UBIRCH_AUTH_MQTT = os.getenv("UBIRCH_AUTH_MQTT")

ICINGA_URL = os.getenv("ICINGA_URL")
ICINGA_AUTH = os.getenv("ICINGA_AUTH")

(MQTT_USER, MQTT_PASS) = (None, None)
if UBIRCH_AUTH_MQTT is not None:
    (MQTT_USER, MQTT_PASS) = UBIRCH_AUTH_MQTT.split(":")

MQTT_PORT = 1883
if UBIRCH_ENV == "dev":
    MQTT_SERVER = "mq.dev.ubirch.com"
elif UBIRCH_ENV == "demo":
    MQTT_SERVER = "mq.demo.ubirch.com"
elif UBIRCH_ENV == "prod":
    MQTT_SERVER = "mq.prod.ubirch.com"
else:
    MQTT_SERVER = "localhost"

logger.debug("UBIRCH_CLIENT = '{}'".format(UBIRCH_CLIENT))
logger.debug("UBIRCH_ENV    = '{}'".format(UBIRCH_ENV))
logger.debug("UBIRCH_AUTH   = '{}'".format(UBIRCH_AUTH))
logger.debug("MQTT_SERVER   = '{}:{}'".format(MQTT_SERVER, MQTT_PORT))
logger.debug("MQTT_USER     = '{}'".format(MQTT_USER))
logger.debug("MQTT_PASS     = '{}'".format(MQTT_PASS))

logger.debug("ICINGA_HOST   = '{}'".format(ICINGA_URL))
logger.debug("ICINGA_AUTH   = '{}'".format(ICINGA_AUTH))
NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_ERROR = 2
NAGIOS_UNKNOWN = 3


def nagios(client, env, service, code, message="OK"):
    if client is None: client = "ubirch"

    if client is not None:
        env = client+"."+env

    data = {
        "exit_status": code,
        "plugin_output": message,
        "check_source": env,
        "ttl": 3600.0
    }

    if ICINGA_URL is not None and ICINGA_AUTH is not None:
        r = requests.post(ICINGA_URL + "?" + "service={}.ubirch.com!{}".format(env, service),
                          json=data, headers={"Accept": "application/json"}, auth=tuple(ICINGA_AUTH.split(":")))
        if r.status_code != 200:
            logger.error("ICINGA CONNECTION FAILED: " + bytes.decode(r.content))

    if code == NAGIOS_OK:
        logger.info("{} service={}.ubirch.com!{} {}"
                    .format(int(datetime.utcnow().timestamp()), env, service, json.dumps(data)))
    elif code == NAGIOS_WARNING:
        logger.info("{} service={}.ubirch.com!{} {}"
                    .format(int(datetime.utcnow().timestamp()), env, service, json.dumps(data)))
    else:
        logger.info("{} service={}.ubirch.com!{} {}"
                    .format(int(datetime.utcnow().timestamp()), env, service, json.dumps(data)))


class Proto(ubirch.Protocol):
    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self.__ks = key_store

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


# test UUID
uuid = UUID(hex=os.getenv('UBIRCH_DEVICE_UUID', "00000000-0000-0000-0000-000000000000"))

# temporary key store with fixed test-key
keystore = ubirch.KeyStore("service-check.jks", 'service-check')
try:
    keystore.find_signing_key(uuid)
    keystore.create_ed25519_keypair(uuid)
except:
    pass

# configure client specific services if we have one instead of core ubirch services
if UBIRCH_CLIENT is not None and UBIRCH_CLIENT.strip():
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
        r = requests.get(api.get_url(service) + "/deepCheck", timeout=1.0)
        try:
            response = r.json()
            if not response['status']:
                ERRORS += 1
                # logger.error("{}.service.{}.deepCheck: FAILED: {} {}"
                #              .format(UBIRCH_ENV, service, r.status_code, response['messages']))
                nagios(UBIRCH_CLIENT, UBIRCH_ENV, service+"-deepCheck", NAGIOS_ERROR, r.status_code + " " + response['messages'])
            else:
                # logger.info("{}.service.{}.deepCheck: OK".format(UBIRCH_ENV, service))
                nagios(UBIRCH_CLIENT, UBIRCH_ENV, service+"-deepCheck", NAGIOS_OK)

        except JSONDecodeError as e:
            ERRORS += 1
            # logger.error("{}.service.{}.deepCheck: FAILED: {} {}"
            #              .format(UBIRCH_ENV, service, r.status_code, bytes.decode(r.content).split('\n')[0]))
            nagios(UBIRCH_CLIENT, UBIRCH_ENV, service+"-deepCheck", NAGIOS_ERROR,
                   "{} {}".format(r.status_code, bytes.decode(r.content).split('\n')[0]))

    except Exception as e:
        ERRORS += 1
        # logger.error("{}.service.{}.deepCheck: FAILED: {}".format(UBIRCH_ENV, service, e.args))
        nagios(UBIRCH_CLIENT, UBIRCH_ENV, service+"-deepCheck", NAGIOS_ERROR, str(e))

if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

sk = keystore.find_signing_key(uuid)
vk = keystore.find_verifying_key(uuid)

# check, register and deregister key
if api.is_identity_registered(uuid):
    # remove any existing key
    api.deregister_identity(str.encode(json.dumps({
        "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
        "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
    })))

# register key
key_registration = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
r = api.register_identity(key_registration)
if r.status_code == requests.codes.ok:
    # logger.info("{}.service.{}.register_identity: OK".format(UBIRCH_ENV, KEY_SERVICE))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-register", NAGIOS_OK)
else:
    # logger.error("{}.service.{}.register_identity: FAILED: {} {}"
    #              .format(UBIRCH_ENV, KEY_SERVICE, r.status_code, bytes.decode(r.content)))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, KEY_SERVICE + "-register", NAGIOS_ERROR,
           "{} {}".format(r.status_code, bytes.decode(r.content)))

# check if the device exists and delete if that is the case
if api.device_exists(uuid):
    api.device_delete(uuid)
    time.sleep(5)

# create a new device on the backend
r = api.device_create({
    "deviceId": str(uuid),
    "deviceTypeKey": "test-sensor",
    "deviceName": str(uuid),
    "hwDeviceId": str(uuid),
    "tags": ["test", "python-client"],
    "deviceProperties": {
        "storesData": False,
        "blockChain": False
    },
    "created": "{}Z".format(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
})
if r.status_code == requests.codes.ok:
    # logger.info("{}.service.{}.device_create: OK".format(UBIRCH_ENV, AVATAR_SERVICE))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, AVATAR_SERVICE + "-device-create", NAGIOS_OK)
    time.sleep(2)
else:
    # logger.error("{}.service.{}.device_create: FAILED: {} {}"
    #              .format(UBIRCH_ENV, AVATAR_SERVICE, r.status_code, bytes.decode(r.content)))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, AVATAR_SERVICE + "-device-create", NAGIOS_ERROR,
           "{} {}".format(r.status_code, bytes.decode(r.content)))

connected_event = threading.Event()
finished_event = threading.Event()
MESSAGES_SENT: list = []


def mqtt_connected(client, userdata, flags, rc):
    if UBIRCH_CLIENT is not None:
        client.subscribe("{}-{}/ubirch/devices/{}/processed".format(UBIRCH_CLIENT, UBIRCH_ENV, str(uuid)), qos=1)
    else:
        client.subscribe("ubirch-{}/ubirch/devices/{}/processed".format(UBIRCH_ENV, str(uuid)), qos=1)


def mqtt_subscribed(client, userdata, mid, granted_qos):
    logger.debug("SUBSCRIBED")
    connected_event.set()


def mqtt_received(client, userdata, msg):
    global ERRORS
    payload = json.loads(bytes.decode(msg.payload))
    message = bytes.fromhex(payload['deviceDataRaw']['mpraw'])
    logger.debug("{}: {}".format(str(msg.topic), str(msg.payload)))
    if message in MESSAGES_SENT:
        MESSAGES_SENT.remove(message)
        logger.info("{}.service.{}.message.mqtt.{}.received: OK"
                    .format(UBIRCH_ENV, AVATAR_SERVICE, payload['deviceMessage']['v']))
    else:
        ERRORS += 1
        logger.error(msg.topic + " " + str(msg.payload))
    if len(MESSAGES_SENT) == 0:
        client.unsubscribe("ubirch-{}/ubirch/devices/{}/processed".format(UBIRCH_ENV, str(uuid)))
        finished_event.set()


client = mqtt.Client(client_id=uuid.hex)
if MQTT_USER is not None and MQTT_PASS is not None:
    client.username_pw_set(MQTT_USER, MQTT_PASS)
if logger.level == logging.DEBUG:
    client.enable_logger(logger)

client.on_connect = mqtt_connected
client.on_subscribe = mqtt_subscribed
client.on_message = mqtt_received
logger.debug("mqtt: connect({}, {})".format(MQTT_SERVER, MQTT_PORT))
client.connect(MQTT_SERVER, MQTT_PORT, 30)
client.loop_start()

# wait until mqtt is connected and subscribed
if not connected_event.wait(timeout=30):
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, "mqtt", NAGIOS_OK, "could not subscribe")
    exit(-1)

# send signed messages
for n in range(1, 6):
    msg = proto.message_signed(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES_SENT.append(msg)
# send chained messages
for n in range(6, 11):
    msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
    MESSAGES_SENT.append(msg)

ERROR_RESULTS = []
# send out prepared messages
for n, msg in enumerate(MESSAGES_SENT.copy()):
    r = api.send(msg)
    logger.debug(binascii.hexlify(msg))
    if r.status_code == requests.codes.accepted:
        logger.info("{}.service.{}.message.{}.send: OK".format(UBIRCH_ENV, AVATAR_SERVICE, n))
    else:
        ERRORS += 1
        logger.info("{}.service.{}.message.{}.send: FAILED: {} {}"
                    .format(UBIRCH_ENV, AVATAR_SERVICE, n, r.status_code, bytes.decode(r.content)))

finished_event.wait(timeout=30)
if len(MESSAGES_SENT) == 0:
    logger.info("{}.service.{}.mqtt: OK".format(UBIRCH_ENV, AVATAR_SERVICE))
else:
    ERRORS += 1
    logger.info("{}.service.{}.mqtt: FAILED: {} messages missing"
                .format(UBIRCH_ENV, AVATAR_SERVICE, len(MESSAGES_SENT)))
client.disconnect()

# delete the device
if api.device_delete(uuid):
    # logger.info("{}.service.{}.device_delete: OK".format(UBIRCH_ENV, AVATAR_SERVICE))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, AVATAR_SERVICE + "-device-delete", NAGIOS_OK)
else:
    ERRORS += 1
    # logger.error("{}.service.{}.device_delete: FAILED".format(UBIRCH_ENV, AVATAR_SERVICE))
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, AVATAR_SERVICE + "-device-delete", NAGIOS_ERROR, "failed")

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
           "{} messages missing, total {} errors".format(len(MESSAGES_SENT), ERRORS))
    logger.error("{} ERRORS".format(ERRORS))
    exit(-1)
else:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_OK)
    logger.info("All Services: OK")
    exit(0)

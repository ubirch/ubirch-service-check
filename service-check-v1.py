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
import time
from datetime import datetime
from json import JSONDecodeError
from uuid import UUID

from ed25519 import SigningKey

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

sk = SigningKey(binascii.unhexlify(os.getenv('UBIRCH_PRIV_KEY')))
vk = sk.get_verifying_key()

logger.debug("UBIRCH_CLIENT        = '{}'".format(UBIRCH_CLIENT))
logger.debug("UBIRCH_ENV           = '{}'".format(UBIRCH_ENV))
logger.debug("UBIRCH_AUTH          = '{}'".format(UBIRCH_AUTH))
logger.debug("UBIRCH_DEVICE_UUID   = '{}'".format(uuid))

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

MESSAGES_SENT: list = []
ERROR_RESULTS = []

# todo # prepare signed messages
# for n in range(1, 4):
#     msg = proto.message_signed(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': n})
#     MESSAGES_SENT.append(msg)
# # prepare chained messages
# for n in range(4, 8):

payload = [
    "v1.0.2-PROD-20180326103205 (v5.6.6)",
    6496,
    3,
    {
        1594155266: 3665,
        1594155326: 3682,
        1594155386: 3695,
        1594155446: 3702,
        1594155506: 3710,
        1594155566: 3715,
        1594155626: 3717,
        1594155686: 3719,
        1594155746: 3720,
        1594155806: 3720,
        1594155866: 3722,
        1594155926: 3723,
        1594155986: 3723,
        1594156046: 3722,
        1594156106: 3719,
        1594156166: 3721,
        1594156226: 3719,
        1594156286: 3720,
        1594156346: 3720,
        1594156406: 3718,
        1594156466: 3719,
        1594156526: 3715,
        1594156586: 3717,
        1594156646: 3717,
        1594156706: 3717,
        1594156766: 3717,
        1594156826: 3714,
        1594156886: 3715,
        1594156946: 3714,
        1594157006: 3715,
        1594157066: 3713,
        1594157126: 3715,
        1594157186: 3713,
        1594157246: 3714,
        1594157306: 3712,
        1594157366: 3713,
        1594157426: 3712,
        1594157486: 3711,
        1594157546: 3712,
        1594157606: 3710,
        1594157666: 3710,
        1594157726: 3708,
        1594157786: 3709,
        1594157846: 3707,
        1594157906: 3708,
        1594157966: 3705,
        1594158026: 3708,
        1594158086: 3706,
        1594158146: 3706,
        1594158206: 3703,
        1594158266: 3704,
        1594158326: 3703,
        1594158386: 3703,
        1594158446: 3700,
        1594158506: 3699,
        1594158566: 3703,
        1594158626: 3700,
        1594158686: 3700,
        1594158746: 3702,
        1594158806: 3699,
        1594158866: 3699,
        1594158926: 3700,
        1594158986: 3698,
        1594159046: 3700,
        1594159106: 3699,
        1594159166: 3699,
        1594159226: 3700,
        1594159286: 3697,
        1594159346: 3698,
        1594159406: 3698,
        1594159466: 3698,
        1594159526: 3698,
        1594159586: 3698,
        1594159646: 3697,
        1594159706: 3697,
        1594159766: 3698,
        1594159826: 3696,
        1594159886: 3698,
        1594159946: 3696,
        1594160006: 3696,
        1594160066: 3696,
        1594160126: 3696,
        1594160186: 3696,
        1594160246: 3696,
        1594160306: 3693,
        1594160366: 3693,
        1594160426: 3692,
        1594160486: 3692,
        1594160546: 3694,
        1594160606: 3692,
        1594160666: 3691,
        1594160726: 3689,
        1594160786: 3692,
        1594160846: 3690,
        1594160906: 3688,
        1594160966: 3687,
        1594161026: 3684,
        1594161086: 3687,
        1594161146: 3687,
        1594161206: 3684,
        1594161266: 3685,
        1594161326: 3684,
        1594161386: 3685,
        1594161446: 3687,
        1594161506: 3685,
        1594161566: 3685,
        1594161626: 3687,
        1594161686: 3688,
        1594161746: 3687,
        1594161806: 3689,
        1594161866: 3688,
        1594161926: 3690,
        1594161986: 3689,
        1594162046: 3688,
        1594162106: 3690,
        1594162166: 3689,
        1594162226: 3691,
        1594162286: 3690,
        1594162346: 3692,
        1594162406: 3691,
        1594162466: 3692,
        1594162526: 3692,
        1594162586: 3692,
        1594162646: 3692,
        1594162706: 3691,
        1594162766: 3690,
        1594162826: 3691,
        1594162886: 3691,
        1594162946: 3689,
        1594163006: 3690,
        1594163066: 3690,
        1594163126: 3689,
        1594163186: 3689,
        1594163246: 3689,
        1594163306: 3689,
        1594163366: 3690,
        1594163426: 3690,
        1594163486: 3691,
        1594163546: 3689,
        1594163606: 3690,
        1594163666: 3688,
        1594163726: 3689,
        1594163786: 3691,
        1594163846: 3689,
        1594163906: 3690,
        1594163966: 3691,
        1594164026: 3691,
        1594164086: 3689,
        1594164146: 3691,
        1594164206: 3692,
        1594164266: 3692,
        1594164326: 3689,
        1594164386: 3690,
        1594164446: 3691,
        1594164506: 3690,
        1594164566: 3689,
        1594164626: 3690,
        1594164686: 3690,
        1594164746: 3689,
        1594164806: 3688,
        1594164866: 3687,
        1594164926: 3688,
        1594164986: 3688,
        1594165046: 3685,
        1594165106: 3685,
        1594165166: 3684,
        1594165226: 3685,
        1594165286: 3684,
        1594165346: 3684,
        1594165406: 3683,
        1594165466: 3682,
        1594165526: 3683,
        1594165586: 3682,
        1594165646: 3683,
        1594165706: 3683,
        1594165766: 3682,
        1594165826: 3681,
        1594165886: 3681,
        1594165946: 3681,
        1594166006: 3678,
        1594166066: 3680,
        1594166126: 3680,
        1594166186: 3679,
        1594166246: 3677,
        1594166306: 3678,
        1594166366: 3678,
        1594166426: 3677,
        1594166486: 3674,
        1594166546: 3674,
        1594166606: 3673,
        1594166666: 3673,
        1594166726: 3671,
        1594166786: 3674,
        1594166846: 3673,
        1594166906: 3673,
        1594166966: 3670,
        1594167026: 3669,
        1594167086: 3669,
        1594167146: 3670,
        1594167206: 3668,
        1594167266: 3669,
        1594167326: 3669,
        1594167386: 3669,
        1594167446: 3670,
        1594167506: 3671,
        1594167566: 3673,
        1594167626: 3674,
        1594167686: 3673,
        1594167746: 3675,
        1594167806: 3675,
        1594167866: 3676,
        1594167926: 3675,
        1594167986: 3673,
        1594168046: 3676,
        1594168106: 3677,
        1594168166: 3677,
        1594168226: 3675,
        1594168286: 3677,
        1594168346: 3679,
        1594168406: 3677,
        1594168466: 3680,
        1594168526: 3678,
        1594168586: 3679,
        1594168646: 3680,
        1594168706: 3680,
        1594168766: 3680,
        1594168826: 3682,
        1594168886: 3681,
        1594168946: 3682,
        1594169006: 3684,
        1594169066: 3682,
        1594169126: 3684,
        1594169186: 3687,
        1594169246: 3685,
        1594169306: 3687,
        1594169366: 3687,
        1594169426: 3688,
        1594169486: 3684,
        1594169546: 3688,
        1594169606: 3688,
        1594169666: 3687,
        1594169726: 3689,
        1594169786: 3690,
        1594169846: 3689,
        1594169906: 3689,
        1594169966: 3689,
        1594170026: 3691,
        1594170086: 3689,
        1594170146: 3691,
        1594170206: 3690,
        1594170266: 3690,
        1594170326: 3690,
        1594170386: 3690,
        1594170446: 3690,
        1594170506: 3691,
        1594170566: 3691,
        1594170626: 3691,
        1594170686: 3689,
        1594170746: 3691,
        1594170806: 3691,
        1594170866: 3692,
        1594170926: 3691,
        1594170986: 3691,
        1594171046: 3690,
        1594171106: 3692,
        1594171166: 3692,
        1594171226: 3691,
        1594171286: 3691,
        1594171346: 3691,
        1594171406: 3691,
        1594171466: 3689,
        1594171526: 3692,
        1594171586: 3692,
        1594171646: 3694,
        1594171706: 3690,
        1594171766: 3690,
        1594171826: 3690,
        1594171886: 3689,
        1594171946: 3690,
        1594172006: 3689,
        1594172066: 3689,
        1594172126: 3689,
        1594172186: 3684,
        1594172246: 3689,
        1594172306: 3688,
        1594172366: 3685,
        1594172426: 3684,
        1594172486: 3684,
        1594172546: 3685,
        1594172606: 3684,
        1594172666: 3684,
        1594172726: 3683,
        1594172786: 3683,
        1594172846: 3685,
        1594172906: 3681,
        1594172966: 3683,
        1594173026: 3681,
        1594173086: 3680,
        1594173146: 3681,
        1594173206: 3679,
        1594173266: 3678,
        1594173326: 3680,
        1594173386: 3679,
        1594173446: 3678,
        1594173506: 3677,
        1594173566: 3674,
        1594173626: 3675,
        1594173686: 3673,
        1594173746: 3673,
        1594173806: 3673,
        1594173866: 3673,
        1594173926: 3673,
        1594173986: 3674,
        1594174046: 3673,
        1594174106: 3675,
        1594174166: 3675,
        1594174226: 3675,
        1594174286: 3677,
        1594174346: 3676,
        1594174406: 3678,
        1594174466: 3677,
        1594174526: 3676,
        1594174586: 3677,
        1594174646: 3678,
        1594174706: 3679,
        1594174766: 3677,
        1594174826: 3677,
        1594174886: 3680,
        1594174946: 3679,
        1594175006: 3680,
        1594175066: 3679,
        1594175126: 3679,
        1594175186: 3680,
        1594175246: 3681,
        1594175306: 3682,
        1594175366: 3681,
        1594175426: 3681,
        1594175486: 3678,
        1594175546: 3682,
        1594175606: 3681,
        1594175666: 3681,
        1594175726: 3681,
        1594175786: 3682,
        1594175846: 3681,
        1594175906: 3683,
        1594175966: 3682,
        1594176026: 3681,
        1594176086: 3682,
        1594176146: 3682,
        1594176206: 3682,
        1594176266: 3682,
        1594176326: 3682,
        1594176386: 3682,
        1594176446: 3684,
        1594176506: 3681,
        1594176566: 3682,
        1594176626: 3685,
        1594176686: 3682,
        1594176746: 3683,
        1594176806: 3685,
        1594176866: 3684,
        1594176926: 3684,
        1594176986: 3685,
        1594177046: 3684,
        1594177106: 3682,
        1594177166: 3682,
        1594177226: 3684,
        1594177286: 3683,
        1594177346: 3683,
        1594177406: 3684,
        1594177466: 3684,
        1594177526: 3681,
        1594177586: 3685,
        1594177646: 3682,
        1594177706: 3684,
        1594177766: 3683,
        1594177826: 3683,
        1594177886: 3684,
        1594177946: 3685,
        1594178006: 3685,
        1594178066: 3684,
        1594178126: 3684,
        1594178186: 3684,
        1594178246: 3685,
        1594178306: 3685,
        1594178366: 3684,
        1594178426: 3683,
        1594178486: 3685,
        1594178546: 3684,
        1594178606: 3683,
        1594178666: 3683,
        1594178726: 3682,
        1594178786: 3683,
        1594178846: 3683,
        1594178906: 3683,
        1594178966: 3682,
        1594179026: 3678,
        1594179086: 3679,
        1594179146: 3678,
        1594179206: 3678,
        1594179266: 3678,
        1594179326: 3680,
        1594179386: 3678,
        1594179446: 3677,
        1594179506: 3677,
        1594179566: 3674,
        1594179626: 3676,
        1594179686: 3675,
        1594179746: 3677,
        1594179806: 3675,
        1594179866: 3675,
        1594179926: 3675,
        1594179986: 3675,
        1594180046: 3673,
        1594180106: 3675,
        1594180166: 3677,
        1594180226: 3675,
        1594180286: 3676,
        1594180346: 3677,
        1594180406: 3678,
        1594180466: 3678,
        1594180526: 3677,
        1594180586: 3678,
        1594180646: 3681,
        1594180706: 3679,
        1594180766: 3680,
        1594180826: 3682,
        1594180886: 3682,
        1594180946: 3682,
        1594181006: 3685,
        1594181066: 3681,
        1594181126: 3683,
        1594181186: 3684,
        1594181246: 3685,
        1594181306: 3684,
        1594181366: 3685,
        1594181426: 3685,
        1594181486: 3687,
        1594181546: 3685,
        1594181606: 3689,
        1594181666: 3688,
        1594181726: 3688,
        1594181786: 3687,
        1594181846: 3688,
        1594181906: 3688,
        1594181966: 3688,
        1594182026: 3689,
        1594182086: 3687,
        1594182146: 3688,
        1594182206: 3688,
        1594182266: 3687,
        1594182326: 3685,
        1594182386: 3688,
        1594182446: 3687,
        1594182506: 3688,
        1594182566: 3688,
        1594182626: 3689,
        1594182686: 3689,
        1594182746: 3689,
        1594182806: 3689,
        1594182866: 3689,
        1594182926: 3690,
        1594182986: 3689,
        1594183046: 3691,
        1594183106: 3691,
        1594183166: 3692,
        1594183226: 3691,
        1594183286: 3691,
        1594183346: 3692,
        1594183406: 3692,
        1594183466: 3691,
        1594183526: 3693,
        1594183586: 3693,
        1594183646: 3694,
        1594183706: 3692,
        1594183766: 3695,
        1594183826: 3693,
        1594183886: 3696,
        1594183946: 3697
    },
    {
        "min": 3500,
        "max": 4200,
        "i": 60000,
        "il": 1800000
    }
]

msg = proto.message_chained(uuid, 0x54, payload)
MESSAGES_SENT.append(msg)

# send out prepared messages
for n, msg in enumerate(MESSAGES_SENT.copy()):
    r = api.send(msg)
    logger.debug(binascii.hexlify(msg))
    if r.status_code == requests.codes.accepted:
        logger.info("{}.service.{}.message.{}.send: OK".format(UBIRCH_ENV, AVATAR_SERVICE, n))
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
           "{} messages missing, total {} errors\n{}".format(len(MESSAGES_SENT), ERRORS, "\n".join(ERROR_RESULTS)))
    logger.error("{} ERRORS".format(ERRORS))
    exit(-1)
else:
    nagios(UBIRCH_CLIENT, UBIRCH_ENV, "ubirch", NAGIOS_OK)
    logger.info("All Services: OK")
    exit(0)

import pytest

import json, msgpack, uuid, base64, hashlib, time, binascii
import os, logging

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN, UNPACKED_UPP_FIELD_PREV_SIG
from helper import Proto, ED25519Certificate, ECDSACertificate, UBIRCH_UUIDS, UBIRCH_PUBKEYS_EC, UBIRCH_PUBKEYS_ED

with open("config.json", "r") as f:
    config = json.load(f)
    TEST_KEY_ED25519 = config["ed25519_key"]
    TEST_KEY_ECDSA = config["ecdsa_key"]

    TEST_UUID_STRING = config["testDevice"]["uuid"]
    TEST_UUID = uuid.UUID(TEST_UUID_STRING)
    TEST_AUTH = config["testDevice"]["password"]

    UBIRCH_ENV = config["env"] # demo is standard

# TODO: FIXME: In GoCD use this to get env vars:
# TEST_KEY_ED25519 = os.getenv("TEST_KEY_EDDSA") # ed25519
# TEST_KEY_ECDSA = os.getenv("TEST_KEY_ECDSA") # ecdsa
# 
# TEST_UUID_STRING = os.getenv("TEST_UUID")
# TEST_UUID = uuid.UUID(TEST_UUID_STRING)
# TEST_AUTH = os.getenv("UBIRCH_AUTH")
# 
# UBIRCH_ENV = os.getenv("UBIRCH_ENV", "demo")

# create an instance of the UBIRCH API and set the auth token
api = ubirch.API(env=UBIRCH_ENV)
api.set_authentication(TEST_UUID, TEST_AUTH)

# Parametrisation of TEST_KEY and KEY_TYPE to test both ed25519 and ecdsa
keys = [("ecdsa", TEST_KEY_ECDSA), ("ed25519", TEST_KEY_ED25519)]

# Fixture to re-create protocol instance for each test
@pytest.fixture(params = keys)
def protocol(request): 
    # request.param contains element in keys
    # returns protocol without Keystore (key saving)
    return Proto(TEST_UUID, request.param[0], request.param[1])

# return protocol where not vk is registered
@pytest.fixture
def protocol_unregistered(protocol):
    if api.is_identity_registered(TEST_UUID):
        # Iterate over all protocols and deregister. Thing must have been registered with one of the keys
        for protocol_tuple in keys:
            iterate_protocol = Proto(TEST_UUID, protocol_tuple[0], protocol_tuple[1])

            r = api.deregister_identity(str.encode(json.dumps({
                "publicKey": bytes.decode(base64.b64encode(iterate_protocol.get_vk())),
                "signature": bytes.decode(base64.b64encode(iterate_protocol.sk.sign(iterate_protocol.get_vk())))
            })))
    return protocol

# return protocol where vk is registered
@pytest.fixture
def protocol_registered(protocol_unregistered):
    # FIXME: Would be more elegant with a 'identity' object fixture
    cert = protocol_unregistered.get_certificate(TEST_UUID)
    key_registration = protocol_unregistered.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_REG, cert)
    api.register_identity(key_registration)
    return protocol_unregistered

# TODO? Does testing the fixtures make sense? 
def test_protocol_fixture():
    pass

n_test_messages = 2

class TestUbirchNiomon:
    @pytest.fixture
    def messages(self, protocol):
        # TODO: Rewrite (maybe pametrize) This code. 
        # Its is a copy-paste from old tests

        messages = []
        hashes = []
        for i in range(n_test_messages):
            data = '{"this_is_a_test":"OK", "t": "' + str(time.time()) + '"}'

            if type == "ECC_ED25519":
                digest = hashlib.sha512(data.encode()).digest()
            else:
                digest = hashlib.sha256(data.encode()).digest()

            # send half signed and half chained messages
            if n_test_messages < n_test_messages / 2:
                msg = protocol.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_BIN, digest)
            else:
                msg = protocol.message_chained(TEST_UUID, UBIRCH_PROTOCOL_TYPE_BIN, digest)
            messages.append([msg, digest, data])
            hashes.append(digest)

        return messages
    
    # @pytest.mark.parametrize("message", [get_messages])
    def test_send_messages(self, protocol_registered, messages):
        for message in messages:
            print(message)
            r = api.send(TEST_UUID, message[0])

            print(r)
            print(r.headers)
            # FIXME!
            verified = protocol_registered.verify_signature(UBIRCH_UUIDS[UBIRCH_ENV], r.content)
            print(verified)

            # https://verify.{UBIRCH_ENV}.ubirch.com/api/upp/verify/record
            # https://verify.{UBIRCH_ENV}.ubirch.com/api/upp
            assert verified
            assert r 


    # Function: API.send(), API._send_mpack()
    # Endpoint: https://niomon.demo.ubirch.com/
    # FIXME: Always an error with the second key!
    @pytest.mark.skip
    def test_send_msgpack(self, protocol_registered):
        raw_test_data = '{"this_is_a_test":"OK", "t": "' + str(time.time()) + '"}'
        test_data = hashlib.sha512(raw_test_data.encode()).digest()
        message_UPP = protocol_registered.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_BIN, test_data)
        r = api.send(TEST_UUID, message_UPP)
        # print(r)
        # r_unpacked = protocol_registered.unpack_upp(r.content)
        # print(r_unpacked)
        # print(binascii.b2a_base64(r_unpacked[1]))
        assert r

    # Function: API.send(), API._send_json()
    # Endpoint: https://niomon.demo.ubirch.com/
    @pytest.mark.skip
    def test_send_json(self, protocol_registered):
        test_data = {"this_is_a_test":"OK", "t":str(time.time()).encode()}
        r = api.send(TEST_UUID, test_data)
        #message_UPP = protocol_registered.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_BIN, test_data)
        #r = api.send(TEST_UUID, message_UPP)
        print(r)
        print(r.content)
        assert r

    """
    def test_send_json_fails(self, mock):
        pass

    def test_send_msgpack_fails(self):
        pass
    """

    # TODO??? Test response headers

class TestUbirchIdentityService:
    # Function: API.is_identity_registered() 
    # Endpoint: https://key.demo.ubirch.com/api/keyService/v1/pubkey/current/hardwareId/{uuid}
    def test_is_identity_registered(self, protocol_registered):
        # 'protocol_registered' assures a pubkey is registered
        assert api.is_identity_registered(TEST_UUID)

    def test_is_identity_registered_not_registered(self, protocol_unregistered):
        # 'protocol' assures NO pubkey is registered
        assert not api.is_identity_registered(uuid.uuid4())

    # Functions: API.register_identity() => API._register_identity_mpack()
    # Endpoint: https://key.demo.ubirch.com/api/keyService/v1/pubkey/mpack
    def test_register_identity_msgpack(self, protocol_unregistered):
        # msgpack.packb([1, 2, 3])
        cert = protocol_unregistered.get_certificate(TEST_UUID)
        key_registration = protocol_unregistered.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_REG, cert)
        response = api.register_identity(key_registration)
        
        assert response # assert response has 2** Code
        #TODO check for response UPP

    def test_register_identity_msgpack_fails(self, protocol_unregistered):
        cert = protocol_unregistered.get_certificate(TEST_UUID)
        cert['pubKey'] = "NO CERT" # Make cert invalid
        cert['pubKeyId'] = "NO CERT"
        key_registration = protocol_unregistered.message_signed(TEST_UUID, UBIRCH_PROTOCOL_TYPE_REG, cert)
        response = api.register_identity(key_registration)

        assert not response # assert response has 4** Code

    # FIXME: How does api.register_identity() need to be called so it calls api._register_identity_json()
    # # Functions: API.register_identity() # API._register_identity_json()
    # # Endpoint: https://key.demo.ubirch.com/api/keyService/v1/pubkey
    # def test_register_identity_json(self, protocol): 
    #     pass
    #     
    # def test_register_identity_json_fails_wrong_cert(self, protocol): 
    #     pass

    # Functions: api.deregister_identity() => api._deregister_identity_json()
    # Endpoint: DELETE https://key.demo.ubirch.com/api/keyService/v1/pubkey
    def test_deregister_identity_json(self, protocol_registered):
        response = api.deregister_identity(str.encode(json.dumps({
            "publicKey": bytes.decode(base64.b64encode(protocol_registered.get_vk())),
            "signature": bytes.decode(base64.b64encode(protocol_registered.sk.sign(protocol_registered.get_vk())))
        })))
        assert response

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.testing.python.jwt_service."""

from absl.testing import absltest
import grpc

from tink import jwt

from proto import testing_api_pb2
import jwt_service
import services


class DummyServicerContext(grpc.ServicerContext):

  def is_active(self):
    pass

  def time_remaining(self):
    pass

  def cancel(self):
    pass

  def add_callback(self, callback):
    pass

  def invocation_metadata(self):
    pass

  def peer(self):
    pass

  def peer_identities(self):
    pass

  def peer_identity_key(self):
    pass

  def auth_context(self):
    pass

  def set_compression(self, compression):
    pass

  def send_initial_metadata(self, initial_metadata):
    pass

  def set_trailing_metadata(self, trailing_metadata):
    pass

  def abort(self, code, details):
    pass

  def abort_with_status(self, status):
    pass

  def set_code(self, code):
    pass

  def set_details(self, details):
    pass

  def disable_next_message_compression(self):
    pass


class JwtServiceTest(absltest.TestCase):

  _ctx = DummyServicerContext()

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    jwt.register_jwt_mac()
    jwt.register_jwt_signature()

  def test_create_jwt_mac(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_hs256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')

    creation_request = testing_api_pb2.CreationRequest(
        keyset=gen_response.keyset)
    creation_response = jwt_servicer.CreateJwtMac(
        creation_request, self._ctx)
    self.assertEmpty(creation_response.err)

  def test_create_jwt_mac_broken_keyset(self):
    jwt_servicer = jwt_service.JwtServicer()

    creation_request = testing_api_pb2.CreationRequest(keyset=b'\x80')
    creation_response = jwt_servicer.CreateJwtMac(creation_request, self._ctx)
    self.assertNotEmpty(creation_response.err)

  def test_generate_compute_verify_mac(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_hs256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    comp_request = testing_api_pb2.JwtSignRequest(keyset=keyset)
    comp_request.raw_jwt.issuer.value = 'issuer'
    comp_request.raw_jwt.subject.value = 'subject'
    comp_request.raw_jwt.custom_claims['myclaim'].bool_value = True
    comp_request.raw_jwt.expiration.seconds = 1334
    comp_request.raw_jwt.expiration.nanos = 123000000

    comp_response = jwt_servicer.ComputeMacAndEncode(comp_request, self._ctx)
    self.assertEqual(comp_response.WhichOneof('result'), 'signed_compact_jwt')
    signed_compact_jwt = comp_response.signed_compact_jwt
    verify_request = testing_api_pb2.JwtVerifyRequest(
        keyset=keyset, signed_compact_jwt=signed_compact_jwt)
    verify_request.validator.expected_issuer.value = 'issuer'
    verify_request.validator.now.seconds = 1234
    verify_response = jwt_servicer.VerifyMacAndDecode(verify_request, self._ctx)
    self.assertEqual(verify_response.WhichOneof('result'), 'verified_jwt')
    self.assertEqual(verify_response.verified_jwt.issuer.value, 'issuer')
    self.assertEqual(verify_response.verified_jwt.subject.value, 'subject')
    self.assertEqual(verify_response.verified_jwt.expiration.seconds, 1334)
    self.assertEqual(verify_response.verified_jwt.expiration.nanos, 0)

  def test_generate_compute_verify_mac_without_expiration(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_hs256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    comp_request = testing_api_pb2.JwtSignRequest(keyset=keyset)
    comp_request.raw_jwt.issuer.value = 'issuer'

    comp_response = jwt_servicer.ComputeMacAndEncode(comp_request, self._ctx)
    self.assertEqual(comp_response.WhichOneof('result'), 'signed_compact_jwt')
    signed_compact_jwt = comp_response.signed_compact_jwt
    verify_request = testing_api_pb2.JwtVerifyRequest(
        keyset=keyset, signed_compact_jwt=signed_compact_jwt)
    verify_request.validator.expected_issuer.value = 'issuer'
    verify_request.validator.allow_missing_expiration = True
    verify_response = jwt_servicer.VerifyMacAndDecode(verify_request, self._ctx)
    print(verify_response.err)
    self.assertEqual(verify_response.WhichOneof('result'), 'verified_jwt')
    self.assertEqual(verify_response.verified_jwt.issuer.value, 'issuer')

  def test_create_public_key_sign(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_es256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')

    creation_request = testing_api_pb2.CreationRequest(
        keyset=gen_response.keyset)
    creation_response = jwt_servicer.CreateJwtPublicKeySign(
        creation_request, self._ctx)
    self.assertEmpty(creation_response.err)

  def test_create_public_key_sign_bad_keyset(self):
    jwt_servicer = jwt_service.JwtServicer()

    creation_request = testing_api_pb2.CreationRequest(keyset=b'\x80')
    creation_response = jwt_servicer.CreateJwtPublicKeySign(
        creation_request, self._ctx)
    self.assertNotEmpty(creation_response.err)

  def test_create_public_key_verify(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_es256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    pub_request = testing_api_pb2.KeysetPublicRequest(
        private_keyset=gen_response.keyset)
    pub_response = keyset_servicer.Public(pub_request, self._ctx)
    self.assertEqual(pub_response.WhichOneof('result'), 'public_keyset')

    creation_request = testing_api_pb2.CreationRequest(
        keyset=pub_response.public_keyset)
    creation_response = jwt_servicer.CreateJwtPublicKeyVerify(
        creation_request, self._ctx)
    self.assertEmpty(creation_response.err)

  def test_create_public_key_verify_bad_keyset(self):
    jwt_servicer = jwt_service.JwtServicer()

    creation_request = testing_api_pb2.CreationRequest(keyset=b'\x80')
    creation_response = jwt_servicer.CreateJwtPublicKeyVerify(
        creation_request, self._ctx)
    self.assertNotEmpty(creation_response.err)

  def test_generate_sign_export_import_verify_signature(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_es256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    private_keyset = gen_response.keyset

    comp_request = testing_api_pb2.JwtSignRequest(keyset=private_keyset)
    comp_request.raw_jwt.issuer.value = 'issuer'
    comp_request.raw_jwt.subject.value = 'subject'
    comp_request.raw_jwt.custom_claims['myclaim'].bool_value = True
    comp_response = jwt_servicer.PublicKeySignAndEncode(comp_request, self._ctx)
    self.assertEqual(comp_response.WhichOneof('result'), 'signed_compact_jwt')
    signed_compact_jwt = comp_response.signed_compact_jwt

    pub_request = testing_api_pb2.KeysetPublicRequest(
        private_keyset=private_keyset)
    pub_response = keyset_servicer.Public(pub_request, self._ctx)
    self.assertEqual(pub_response.WhichOneof('result'), 'public_keyset')
    public_keyset = pub_response.public_keyset

    to_jwkset_request = testing_api_pb2.JwtToJwkSetRequest(keyset=public_keyset)
    to_jwkset_response = jwt_servicer.ToJwkSet(to_jwkset_request, self._ctx)
    self.assertEqual(to_jwkset_response.WhichOneof('result'), 'jwk_set')

    self.assertStartsWith(to_jwkset_response.jwk_set, '{"keys":[{"')

    from_jwkset_request = testing_api_pb2.JwtFromJwkSetRequest(
        jwk_set=to_jwkset_response.jwk_set)
    from_jwkset_response = jwt_servicer.FromJwkSet(
        from_jwkset_request, self._ctx)
    self.assertEqual(from_jwkset_response.WhichOneof('result'), 'keyset')

    verify_request = testing_api_pb2.JwtVerifyRequest(
        keyset=from_jwkset_response.keyset,
        signed_compact_jwt=signed_compact_jwt)
    verify_request.validator.expected_issuer.value = 'issuer'
    verify_request.validator.allow_missing_expiration = True
    verify_response = jwt_servicer.PublicKeyVerifyAndDecode(
        verify_request, self._ctx)
    self.assertEqual(verify_response.WhichOneof('result'), 'verified_jwt')
    self.assertEqual(verify_response.verified_jwt.issuer.value, 'issuer')

  def test_to_jwk_set_with_invalid_keyset_fails(self):
    jwt_servicer = jwt_service.JwtServicer()

    to_jwkset_request = testing_api_pb2.JwtToJwkSetRequest(keyset=b'invalid')
    jwkset_response = jwt_servicer.ToJwkSet(to_jwkset_request, self._ctx)
    self.assertEqual(jwkset_response.WhichOneof('result'), 'err')

  def test_from_jwk_set_with_invalid_jwk_set_fails(self):
    jwt_servicer = jwt_service.JwtServicer()

    from_jwkset_request = testing_api_pb2.JwtFromJwkSetRequest(
        jwk_set='invalid')
    from_jwkset_response = jwt_servicer.FromJwkSet(from_jwkset_request,
                                                   self._ctx)
    self.assertEqual(from_jwkset_response.WhichOneof('result'), 'err')
    print(from_jwkset_response.err)


if __name__ == '__main__':
  absltest.main()

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

from proto.testing import testing_api_pb2
from tink import jwt
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

  def test_generate_compute_verify_mac(self):
    keyset_servicer = services.KeysetServicer()
    jwt_servicer = jwt_service.JwtServicer()

    template = jwt.jwt_hs256_template().SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    comp_request = testing_api_pb2.JwtSignRequest(keyset=keyset)
    comp_request.raw_jwt.type_header.value = 'type_header'
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
    verify_request.validator.issuer.value = 'issuer'
    verify_request.validator.now.seconds = 1234
    verify_response = jwt_servicer.VerifyMacAndDecode(verify_request, self._ctx)
    self.assertEqual(verify_response.WhichOneof('result'), 'verified_jwt')
    self.assertEqual(verify_response.verified_jwt.type_header.value,
                     'type_header')
    self.assertEqual(verify_response.verified_jwt.issuer.value, 'issuer')
    self.assertEqual(verify_response.verified_jwt.subject.value, 'subject')
    self.assertEqual(verify_response.verified_jwt.expiration.seconds, 1334)
    self.assertEqual(verify_response.verified_jwt.expiration.nanos, 123000000)


if __name__ == '__main__':
  absltest.main()

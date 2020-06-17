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
"""Tests for tink.tools.testing.python.testing_server."""

from absl import logging
from absl.testing import absltest
import grpc

from tink import aead


from proto.testing import testing_api_pb2
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


class ServicesTest(absltest.TestCase):

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    aead.register()

  def test_generate_encrypt_decrypt(self):
    keyset_servicer = services.KeysetServicer()
    aead_servicer = services.AeadServicer()

    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.GenerateKeysetRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, DummyServicerContext())
    self.assertEmpty(gen_response.err)
    keyset = gen_response.keyset
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=keyset, plaintext=plaintext, associated_data=associated_data)
    enc_response = aead_servicer.Encrypt(enc_request, DummyServicerContext())
    self.assertEmpty(enc_response.err)
    ciphertext = enc_response.ciphertext
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = aead_servicer.Decrypt(dec_request, DummyServicerContext())
    self.assertEmpty(dec_response.err)
    self.assertEqual(dec_response.plaintext, plaintext)

  def test_generate_decrypt_fail(self):
    keyset_servicer = services.KeysetServicer()
    aead_servicer = services.AeadServicer()

    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.GenerateKeysetRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, DummyServicerContext())
    self.assertEmpty(gen_response.err)
    keyset = gen_response.keyset

    ciphertext = b'some invalid ciphertext'
    associated_data = b'associated_data'
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = aead_servicer.Decrypt(dec_request, DummyServicerContext())
    logging.info('Error in response: %s', dec_response.err)
    self.assertNotEmpty(dec_response.err)
    self.assertEmpty(dec_response.plaintext)

  def test_server_info(self):
    metadata_servicer = services.MetadataServicer()
    request = testing_api_pb2.ServerInfoRequest()
    response = metadata_servicer.GetServerInfo(request, DummyServicerContext())
    self.assertEqual(response.language, 'python')


if __name__ == '__main__':
  absltest.main()

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
from tink import daead
from tink import mac


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

  _ctx = DummyServicerContext()

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    aead.register()
    daead.register()
    mac.register()

  def test_generate_encrypt_decrypt(self):
    keyset_servicer = services.KeysetServicer()
    aead_servicer = services.AeadServicer()

    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=keyset, plaintext=plaintext, associated_data=associated_data)
    enc_response = aead_servicer.Encrypt(enc_request, self._ctx)
    self.assertEqual(enc_response.WhichOneof('result'), 'ciphertext')
    ciphertext = enc_response.ciphertext
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = aead_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'plaintext')
    self.assertEqual(dec_response.plaintext, plaintext)

  def test_generate_decrypt_fail(self):
    keyset_servicer = services.KeysetServicer()
    aead_servicer = services.AeadServicer()

    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    ciphertext = b'some invalid ciphertext'
    associated_data = b'associated_data'
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = aead_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'err')
    logging.info('Error in response: %s', dec_response.err)
    self.assertNotEmpty(dec_response.err)

  def test_server_info(self):
    metadata_servicer = services.MetadataServicer()
    request = testing_api_pb2.ServerInfoRequest()
    response = metadata_servicer.GetServerInfo(request, self._ctx)
    self.assertEqual(response.language, 'python')

  def test_generate_encrypt_decrypt_deterministically(self):
    keyset_servicer = services.KeysetServicer()
    daead_servicer = services.DeterministicAeadServicer()

    template_proto = daead.deterministic_aead_key_templates.AES256_SIV
    template = template_proto.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    enc_request = testing_api_pb2.DeterministicAeadEncryptRequest(
        keyset=keyset, plaintext=plaintext, associated_data=associated_data)
    enc_response = daead_servicer.EncryptDeterministically(enc_request,
                                                           self._ctx)
    self.assertEqual(enc_response.WhichOneof('result'), 'ciphertext')
    enc_response2 = daead_servicer.EncryptDeterministically(enc_request,
                                                            self._ctx)
    self.assertEqual(enc_response2.WhichOneof('result'), 'ciphertext')
    self.assertEqual(enc_response2.ciphertext, enc_response.ciphertext)
    ciphertext = enc_response.ciphertext
    dec_request = testing_api_pb2.DeterministicAeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = daead_servicer.DecryptDeterministically(dec_request,
                                                           self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'plaintext')
    self.assertEqual(dec_response.plaintext, plaintext)

  def test_generate_decrypt_deterministically_fail(self):
    keyset_servicer = services.KeysetServicer()
    daead_servicer = services.DeterministicAeadServicer()

    template_proto = daead.deterministic_aead_key_templates.AES256_SIV
    template = template_proto.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    ciphertext = b'some invalid ciphertext'
    associated_data = b'associated_data'
    dec_request = testing_api_pb2.DeterministicAeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = daead_servicer.DecryptDeterministically(dec_request,
                                                           self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'err')
    logging.info('Error in response: %s', dec_response.err)
    self.assertNotEmpty(dec_response.err)

  def test_generate_compute_verify_mac(self):
    keyset_servicer = services.KeysetServicer()
    mac_servicer = services.MacServicer()

    template = mac.mac_key_templates.HMAC_SHA256_128BITTAG.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset
    data = b'The quick brown fox jumps over the lazy dog'
    comp_request = testing_api_pb2.ComputeMacRequest(keyset=keyset, data=data)
    comp_response = mac_servicer.ComputeMac(comp_request, self._ctx)
    self.assertEqual(comp_response.WhichOneof('result'), 'mac_value')
    mac_value = comp_response.mac_value
    verify_request = testing_api_pb2.VerifyMacRequest(
        keyset=keyset, mac_value=mac_value, data=data)
    verify_response = mac_servicer.VerifyMac(verify_request, self._ctx)
    self.assertEmpty(verify_response.err)

  def test_generate_compute_verify_mac_fail(self):
    keyset_servicer = services.KeysetServicer()
    mac_servicer = services.MacServicer()

    template = mac.mac_key_templates.HMAC_SHA256_128BITTAG.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    verify_request = testing_api_pb2.VerifyMacRequest(
        keyset=keyset, mac_value=b'invalid mac_value', data=b'data')
    verify_response = mac_servicer.VerifyMac(verify_request, self._ctx)
    logging.info('Error in response: %s', verify_response.err)
    self.assertNotEmpty(verify_response.err)


if __name__ == '__main__':
  absltest.main()

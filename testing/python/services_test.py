# Copyright 2020 Google LLC
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
"""Tests for tink.tools.testing.python.testing_server."""

from absl import logging
from absl.testing import absltest
import grpc

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead


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
    hybrid.register()
    prf.register()
    signature.register()
    streaming_aead.register()

  def test_from_json(self):
    keyset_servicer = services.KeysetServicer()
    json_keyset = """
        {
          "primaryKeyId": 42,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "keyMaterialType": "SYMMETRIC",
                "value": "AFakeTestKeyValue1234567"

              },
              "outputPrefixType": "TINK",
              "keyId": 42,
              "status": "ENABLED"
            }
          ]
        }"""
    request = testing_api_pb2.KeysetFromJsonRequest(json_keyset=json_keyset)
    response = keyset_servicer.FromJson(request, self._ctx)
    self.assertEqual(response.WhichOneof('result'), 'keyset')
    keyset = tink.BinaryKeysetReader(response.keyset).read()
    self.assertEqual(keyset.primary_key_id, 42)
    self.assertLen(keyset.key, 1)

  def test_from_json_fail(self):
    keyset_servicer = services.KeysetServicer()
    request = testing_api_pb2.KeysetFromJsonRequest(json_keyset='bad json')
    response = keyset_servicer.FromJson(request, self._ctx)
    self.assertEqual(response.WhichOneof('result'), 'err')
    self.assertNotEmpty(response.err)

  def test_generate_to_from_json(self):
    keyset_servicer = services.KeysetServicer()

    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    tojson_request = testing_api_pb2.KeysetToJsonRequest(keyset=keyset)
    tojson_response = keyset_servicer.ToJson(tojson_request, self._ctx)
    self.assertEqual(tojson_response.WhichOneof('result'), 'json_keyset')
    json_keyset = tojson_response.json_keyset

    fromjson_request = testing_api_pb2.KeysetFromJsonRequest(
        json_keyset=json_keyset)
    fromjson_response = keyset_servicer.FromJson(fromjson_request, self._ctx)
    self.assertEqual(fromjson_response.WhichOneof('result'), 'keyset')
    self.assertEqual(fromjson_response.keyset, keyset)

  def test_to_json_fail(self):
    keyset_servicer = services.KeysetServicer()
    request = testing_api_pb2.KeysetToJsonRequest(keyset=b'bad keyset')
    response = keyset_servicer.ToJson(request, self._ctx)
    self.assertEqual(response.WhichOneof('result'), 'err')
    self.assertNotEmpty(response.err)

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

  def test_generate_hybrid_encrypt_decrypt(self):
    keyset_servicer = services.KeysetServicer()
    hybrid_servicer = services.HybridServicer()

    tp = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    template = tp.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEmpty(gen_response.err)
    private_keyset = gen_response.keyset

    pub_request = testing_api_pb2.KeysetPublicRequest(
        private_keyset=private_keyset)
    pub_response = keyset_servicer.Public(pub_request, self._ctx)
    self.assertEqual(pub_response.WhichOneof('result'), 'public_keyset')
    public_keyset = pub_response.public_keyset

    plaintext = b'The quick brown fox jumps over the lazy dog'
    context_info = b'context_info'
    enc_request = testing_api_pb2.HybridEncryptRequest(
        public_keyset=public_keyset,
        plaintext=plaintext,
        context_info=context_info)
    enc_response = hybrid_servicer.Encrypt(enc_request, self._ctx)
    self.assertEqual(enc_response.WhichOneof('result'), 'ciphertext')
    ciphertext = enc_response.ciphertext

    dec_request = testing_api_pb2.HybridDecryptRequest(
        private_keyset=private_keyset,
        ciphertext=ciphertext,
        context_info=context_info)
    dec_response = hybrid_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'plaintext')
    self.assertEqual(dec_response.plaintext, plaintext)

  def test_generate_hybrid_encrypt_decrypt_fail(self):
    keyset_servicer = services.KeysetServicer()
    hybrid_servicer = services.HybridServicer()

    tp = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    template = tp.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    private_keyset = gen_response.keyset

    dec_request = testing_api_pb2.HybridDecryptRequest(
        private_keyset=private_keyset,
        ciphertext=b'invalid ciphertext',
        context_info=b'context_info')
    dec_response = hybrid_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'err')
    self.assertNotEmpty(dec_response.err)

  def test_sign_verify(self):
    keyset_servicer = services.KeysetServicer()
    signature_servicer = services.SignatureServicer()

    template = signature.signature_key_templates.ECDSA_P256.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)

    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    private_keyset = gen_response.keyset

    pub_request = testing_api_pb2.KeysetPublicRequest(
        private_keyset=private_keyset)
    pub_response = keyset_servicer.Public(pub_request, self._ctx)
    self.assertEqual(pub_response.WhichOneof('result'), 'public_keyset')
    public_keyset = pub_response.public_keyset

    data = b'The quick brown fox jumps over the lazy dog'

    sign_request = testing_api_pb2.SignatureSignRequest(
        private_keyset=private_keyset,
        data=data)
    sign_response = signature_servicer.Sign(sign_request, self._ctx)
    self.assertEqual(sign_response.WhichOneof('result'), 'signature')
    a_signature = sign_response.signature

    verify_request = testing_api_pb2.SignatureVerifyRequest(
        public_keyset=public_keyset,
        signature=a_signature,
        data=data)
    verify_response = signature_servicer.Verify(verify_request, self._ctx)
    self.assertEmpty(verify_response.err)

  def test_sign_verify_fail(self):
    keyset_servicer = services.KeysetServicer()
    signature_servicer = services.SignatureServicer()

    template = signature.signature_key_templates.ECDSA_P256.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    self.assertEmpty(gen_response.err)
    private_keyset = gen_response.keyset

    pub_request = testing_api_pb2.KeysetPublicRequest(
        private_keyset=private_keyset)
    pub_response = keyset_servicer.Public(pub_request, self._ctx)
    self.assertEqual(pub_response.WhichOneof('result'), 'public_keyset')
    public_keyset = pub_response.public_keyset

    invalid_request = testing_api_pb2.SignatureVerifyRequest(
        public_keyset=public_keyset,
        signature=b'invalid signature',
        data=b'The quick brown fox jumps over the lazy dog')
    invalid_response = signature_servicer.Verify(invalid_request, self._ctx)
    self.assertNotEmpty(invalid_response.err)

  def test_compute_prf(self):
    keyset_servicer = services.KeysetServicer()
    prf_set_servicer = services.PrfSetServicer()
    template = prf.prf_key_templates.HMAC_SHA256.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    key_ids_request = testing_api_pb2.PrfSetKeyIdsRequest(keyset=keyset)
    key_ids_response = prf_set_servicer.KeyIds(key_ids_request, self._ctx)
    self.assertEqual(key_ids_response.WhichOneof('result'), 'output')
    self.assertLen(key_ids_response.output.key_id, 1)
    self.assertEqual(key_ids_response.output.key_id[0],
                     key_ids_response.output.primary_key_id)

    output_length = 31
    compute_request = testing_api_pb2.PrfSetComputeRequest(
        keyset=keyset,
        key_id=key_ids_response.output.primary_key_id,
        input_data=b'input_data',
        output_length=output_length)
    compute_response = prf_set_servicer.Compute(compute_request, self._ctx)
    self.assertEqual(compute_response.WhichOneof('result'), 'output')
    self.assertLen(compute_response.output, output_length)

  def test_key_ids_prf_fail(self):
    prf_set_servicer = services.PrfSetServicer()
    invalid_key_ids_response = prf_set_servicer.KeyIds(
        testing_api_pb2.PrfSetKeyIdsRequest(keyset=b'badkeyset'), self._ctx)
    self.assertNotEmpty(invalid_key_ids_response.err)

  def test_compute_prf_fail(self):
    keyset_servicer = services.KeysetServicer()
    prf_set_servicer = services.PrfSetServicer()
    template = prf.prf_key_templates.HMAC_SHA256.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset
    key_ids_request = testing_api_pb2.PrfSetKeyIdsRequest(keyset=keyset)
    key_ids_response = prf_set_servicer.KeyIds(key_ids_request, self._ctx)
    self.assertEqual(key_ids_response.WhichOneof('result'), 'output')
    primary_key_id = key_ids_response.output.primary_key_id

    invalid_output_length = 123456
    invalid_compute_request = testing_api_pb2.PrfSetComputeRequest(
        keyset=keyset,
        key_id=primary_key_id,
        input_data=b'input_data',
        output_length=invalid_output_length)
    invalid_compute_response = prf_set_servicer.Compute(invalid_compute_request,
                                                        self._ctx)
    self.assertEqual(invalid_compute_response.WhichOneof('result'), 'err')
    self.assertNotEmpty(invalid_compute_response.err)

  def test_generate_streaming_encrypt_decrypt(self):
    keyset_servicer = services.KeysetServicer()
    streaming_aead_servicer = services.StreamingAeadServicer()

    templates = streaming_aead.streaming_aead_key_templates
    template = templates.AES128_CTR_HMAC_SHA256_4KB.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'

    enc_request = testing_api_pb2.StreamingAeadEncryptRequest(
        keyset=keyset, plaintext=plaintext, associated_data=associated_data)
    enc_response = streaming_aead_servicer.Encrypt(enc_request, self._ctx)
    self.assertEqual(enc_response.WhichOneof('result'), 'ciphertext')
    ciphertext = enc_response.ciphertext

    dec_request = testing_api_pb2.StreamingAeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = streaming_aead_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'plaintext')

    self.assertEqual(dec_response.plaintext, plaintext)

  def test_generate_streaming_decrypt_fail(self):
    keyset_servicer = services.KeysetServicer()
    streaming_aead_servicer = services.StreamingAeadServicer()

    templates = streaming_aead.streaming_aead_key_templates
    template = templates.AES128_CTR_HMAC_SHA256_4KB.SerializeToString()
    gen_request = testing_api_pb2.KeysetGenerateRequest(template=template)
    gen_response = keyset_servicer.Generate(gen_request, self._ctx)
    self.assertEqual(gen_response.WhichOneof('result'), 'keyset')
    keyset = gen_response.keyset

    ciphertext = b'some invalid ciphertext'
    associated_data = b'associated_data'
    dec_request = testing_api_pb2.StreamingAeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = streaming_aead_servicer.Decrypt(dec_request, self._ctx)
    self.assertEqual(dec_response.WhichOneof('result'), 'err')
    logging.info('Error in response: %s', dec_response.err)
    self.assertNotEmpty(dec_response.err)


if __name__ == '__main__':
  absltest.main()

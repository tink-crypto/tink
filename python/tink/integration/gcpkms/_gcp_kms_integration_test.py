# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Integration Tests for Tink GCP KMS integration."""

import base64
import os

from absl.testing import absltest

import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink.integration import gcpkms
from tink.testing import helper

CREDENTIAL_PATH = os.path.join(
    helper.tink_py_testdata_path(), 'gcp/credential.json'
)
BAD_CREDENTIAL_PATH = os.path.join(
    helper.tink_py_testdata_path(), 'gcp/credential_bad.json'
)

KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'
KEY2_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead2-key'


if 'TEST_SRCDIR' in os.environ:
  # Set root certificates for gRPC in Bazel Test which are needed on MacOS
  os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = os.path.join(
      os.environ['TEST_SRCDIR'], 'google_root_pem/file/downloaded')


def setUpModule():
  aead.register()
  # Make an unbound registration.
  gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)


class GcpKmsIntegrationTest(absltest.TestCase):

  def test_aead_from_keyset_handle_for_key_uri_works(self):
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY_URI)
    )
    gcp_aead = handle.primitive(aead.Aead)

    ciphertext = gcp_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', gcp_aead.decrypt(ciphertext, b'associated_data')
    )
    with self.assertRaises(tink.TinkError):
      gcp_aead.decrypt(ciphertext, b'invalid')

  def test_envelope_aead_from_keyset_handle(self):
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            KEY_URI, aead.aead_key_templates.AES128_GCM_SIV
        )
    )
    envelope_aead = handle.primitive(aead.Aead)

    ciphertext = envelope_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', envelope_aead.decrypt(ciphertext, b'associated_data')
    )
    with self.assertRaises(tink.TinkError):
      envelope_aead.decrypt(ciphertext, b'invalid')

  def test_aead_from_keyset_handle_for_key2_uri(self):
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY2_URI)
    )
    gcp_aead = handle.primitive(aead.Aead)

    ciphertext = gcp_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', gcp_aead.decrypt(ciphertext, b'associated_data')
    )

  def test_aead_from_keyset_handle_with_invalid_key_uri_fails(self):
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(
            'aws-kms://arn:aws:kms:us-west-2:acc:other/key3'
        )
    )
    with self.assertRaises(tink.TinkError):
      gcp_aead = handle.primitive(aead.Aead)
      gcp_aead.encrypt(b'plaintext', b'associated_data')

  def test_decrypt_ciphertext_encrypted_in_bigquery_using_a_wrapped_keyset(
      self,
  ):
    # This wrapped keyset was generated in BigQuery using this command:
    # DECLARE kms_key_uri STRING;
    # SET kms_key_uri =
    # 'gcp-kms://projects/tink-test-infrastructure/locations/us/keyRings/big-query-test-key/cryptoKeys/aead-key';
    # SELECT KEYS.NEW_WRAPPED_KEYSET(kms_key_uri, 'AEAD_AES_GCM_256')
    wrapped_keyset = base64.urlsafe_b64decode(
        'CiQAv82D2I7RT2gQRd/01m+Md8WAmOyehVog50vs5uPq2B+R36YSlQEAba+J9rC0gfmX9F'
        'Ss8PsWIpCVbIvPiflsaHRxq5GQjknVgYuJLIMDXlGhQBa3NrfJSmj1T/KDHQ3EzCcPAXtO'
        'AbAExZr/7jsgiCzo/YQINyPb2rGkW4ofo/BVyvhZ/Pk40iuPHv8Q/PXVrNsq3Y2vkkpsyb'
        '3QUhJZseURGjjeQnZde6i3EmvDejXhOZJ3XdQUjwgorA=='
    )

    # This ciphertext was generated in BigQuery using this command:
    # DECLARE kms_key_uri STRING;
    # DECLARE wrapped_key BYTES;
    # SET kms_key_uri =
    # 'gcp-kms://projects/tink-test-infrastructure/locations/us/keyRings/big-query-test-key/cryptoKeys/aead-key';
    # SET wrapped_key =
    # FROM_BASE64('CiQAv82D2I7RT2gQRd/01m+Md8WAmOyehVog50vs5uPq2B+R36YSlQEAba+J9rC0gfmX9FSs8PsWIpCVbIvPiflsaHRxq5GQjknVgYuJLIMDXlGhQBa3NrfJSmj1T/KDHQ3EzCcPAXtOAbAExZr/7jsgiCzo/YQINyPb2rGkW4ofo/BVyvhZ/Pk40iuPHv8Q/PXVrNsq3Y2vkkpsyb3QUhJZseURGjjeQnZde6i3EmvDejXhOZJ3XdQUjwgorA==');
    # SELECT AEAD.ENCRYPT(KEYS.KEYSET_CHAIN(kms_key_uri, wrapped_key),
    #     'elephant', 'animal') AS encrypted_animal;
    ciphertext = base64.urlsafe_b64decode(
        'AcpCNBevmQnr9momhlKKEyKDOCj5bMfizqC22N/hLZd58LFpC+r99C0='
    )

    key_uri = 'gcp-kms://projects/tink-test-infrastructure/locations/us/keyRings/big-query-test-key/cryptoKeys/aead-key'
    gcp_aead_keyset_handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(key_uri)
    )
    gcp_aead = gcp_aead_keyset_handle.primitive(aead.Aead)

    unwrapped_keyset = gcp_aead.decrypt(wrapped_keyset, b'')
    keyset_handle = cleartext_keyset_handle.read(
        tink.BinaryKeysetReader(unwrapped_keyset))
    primitive = keyset_handle.primitive(aead.Aead)
    decrypted = primitive.decrypt(ciphertext, b'animal')
    self.assertEqual(decrypted, b'elephant')


if __name__ == '__main__':
  absltest.main()

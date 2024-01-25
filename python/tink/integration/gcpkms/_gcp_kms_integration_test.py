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
from tink import _kms_clients
from tink import aead
from tink import secret_key_access
from tink.integration import gcpkms
from tink.testing import helper

CREDENTIAL_PATH = os.path.join(
    helper.tink_py_testdata_path(), 'gcp/credential.json'
)
BAD_CREDENTIAL_PATH = os.path.join(
    helper.tink_py_testdata_path(), 'gcp/credential_bad.json'
)

KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'
LOCAL_KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/europe-west1/keyRings/unit-and-integration-test/cryptoKeys/aead-key'
KEY2_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead2-key'

if 'TEST_SRCDIR' in os.environ:
  # Set root certificates for gRPC in Bazel Test which are needed on MacOS
  os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = os.path.join(
      os.environ['TEST_SRCDIR'], 'google_root_pem/file/downloaded')


def setUpModule():
  aead.register()


class GcpKmsIntegrationTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    # Make sure default credentials are not set.
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = ''

  def tearDown(self):
    super().tearDown()
    _kms_clients.reset_kms_clients()

  def test_aead_from_keyset_handle_for_key_uri_works(self):
    # Register client not bound to a key URI.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)

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
    # Register client not bound to a key URI.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)

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

  def test_get_aead_is_compatible_with_kms_aead_key(self):
    # Get aead directly from GCP KMS client.
    kms_aead = gcpkms.GcpKmsClient('', CREDENTIAL_PATH).get_aead(KEY_URI)

    # Get aead by registering a client, and create a keyset with a KmsAeadKey.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY_URI)
    )
    aead_from_kms_aead_key = handle.primitive(aead.Aead)

    # Verify that they are compatible.
    ciphertext = kms_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext',
        aead_from_kms_aead_key.decrypt(ciphertext, b'associated_data'),
    )

  def test_kms_envelope_aead_is_compatible(self):
    # Get aead directly from GCP KMS client, and create an EnvelopeAead.
    kms_aead = gcpkms.GcpKmsClient('', CREDENTIAL_PATH).get_aead(KEY_URI)
    envelope_aead = aead.KmsEnvelopeAead(
        aead.aead_key_templates.AES128_GCM_SIV, kms_aead
    )

    # Get envelope aead by registering a client, and create a keyset with a
    # KmsEnvelopeAeadKey.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)

    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            KEY_URI, aead.aead_key_templates.AES128_GCM_SIV
        )
    )
    aead_from_kms_envelope_aead_key = handle.primitive(aead.Aead)

    # Verify that they are compatible.
    ciphertext = envelope_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext',
        aead_from_kms_envelope_aead_key.decrypt(ciphertext, b'associated_data'),
    )

  def test_aead_from_keyset_handle_for_key2_uri(self):
    # Register client not bound to a key URI.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)

    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY2_URI)
    )
    gcp_aead = handle.primitive(aead.Aead)

    ciphertext = gcp_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', gcp_aead.decrypt(ciphertext, b'associated_data')
    )

  def test_aead_from_keyset_handle_with_invalid_key_uri_fails(self):
    # Register client not bound to a key URI.
    gcpkms.GcpKmsClient.register_client('', CREDENTIAL_PATH)

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
    gcp_aead = gcpkms.GcpKmsClient('', CREDENTIAL_PATH).get_aead(key_uri)

    unwrapped_keyset = gcp_aead.decrypt(wrapped_keyset, b'')
    keyset_handle = tink.proto_keyset_format.parse(
        unwrapped_keyset, secret_key_access.TOKEN
    )
    primitive = keyset_handle.primitive(aead.Aead)
    decrypted = primitive.decrypt(ciphertext, b'animal')
    self.assertEqual(decrypted, b'elephant')

  def test_registration_client_bound_to_uri_works(self):
    # Register client bound to KEY_URI.
    gcpkms.GcpKmsClient.register_client(KEY_URI, CREDENTIAL_PATH)

    # Create a keyset handle for KEY_URI and use it. This works.
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY_URI)
    )
    gcp_aead = handle.primitive(aead.Aead)
    ciphertext = gcp_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', gcp_aead.decrypt(ciphertext, b'associated_data')
    )

    # But it fails for LOCAL_KEY_URI, since the URI is different.
    with self.assertRaises(tink.TinkError):
      handle2 = tink.new_keyset_handle(
          aead.aead_key_templates.create_kms_aead_key_template(LOCAL_KEY_URI)
      )
      gcp_aead = handle2.primitive(aead.Aead)
      gcp_aead.encrypt(b'plaintext', b'associated_data')

  def test_registration_client_with_default_credentials_works(self):
    # Set default credentials, see
    # https://cloud.google.com/docs/authentication/application-default-credentials
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = CREDENTIAL_PATH

    # register_client with credentials_path=None will use the default
    # credentials.
    gcpkms.GcpKmsClient.register_client(key_uri=KEY2_URI, credentials_path=None)

    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY2_URI)
    )
    gcp_aead = handle.primitive(aead.Aead)
    ciphertext = gcp_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', gcp_aead.decrypt(ciphertext, b'associated_data')
    )


if __name__ == '__main__':
  absltest.main()

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
"""Tests for _hcvault_kms_aead.py."""

import base64
import http.server
import json
import re
import threading
from absl.testing import absltest
from absl.testing import parameterized
import hvac
import tink
from tink import aead
from tink.integration import hcvault

_TOKEN = ''
_KEY_PATH = 'transit/keys/key-1'
_PORT = 8205
_VAULT_URI = f'http://localhost:{_PORT}'


_KEY_NAME_TO_AEAD = {}


def _new_aead() -> aead.Aead:
  handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
  return handle.primitive(aead.Aead)


def setUpModule():
  global _KEY_NAME_TO_AEAD
  aead.register()
  _KEY_NAME_TO_AEAD = {k: _new_aead() for k in ['key-1', 'key-2']}


class MockHandler(http.server.BaseHTTPRequestHandler):

  def do_POST(self):  # pylint: disable=invalid-name
    path_prefix, key_name = self.path.rsplit('/', 1)
    if key_name not in _KEY_NAME_TO_AEAD:
      self.send_error(404)
      return
    if path_prefix == '/v1/transit/encrypt':
      post_body = self.rfile.read(int(self.headers.get('Content-Length')))
      req = json.loads(post_body)
      ret = self.encrypt(key_name, req)
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.end_headers()
      self.wfile.write(ret.encode('utf-8'))
      return

    if path_prefix == '/v1/transit/decrypt':
      try:
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        req = json.loads(post_body)
        ret = self.decrypt(key_name, req)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(ret.encode('utf-8'))
      except (OSError, BlockingIOError):
        self.send_error(400)
      return

    self.send_error(404)

  def do_GET(self):  # pylint: disable=invalid-name
    self.send_error(404)

  def do_PUT(self):  # pylint: disable=invalid-name
    self.send_error(404)

  def encrypt(self, key_name, data):
    plaintext = base64.b64decode(data['plaintext'])
    context = base64.b64decode(data['context'])
    ciphertext = _KEY_NAME_TO_AEAD[key_name].encrypt(plaintext, context)
    resp = {'ciphertext': base64.b64encode(ciphertext).decode()}
    return json.dumps({'data': resp})

  def decrypt(self, key_name, data):
    ciphertext = base64.b64decode(data['ciphertext'])
    context = base64.b64decode(data['context'])
    plaintext = _KEY_NAME_TO_AEAD[key_name].decrypt(ciphertext, context)
    resp = {'plaintext': base64.b64encode(plaintext).decode()}
    return json.dumps({'data': resp})


class HcVaultKmsAeadTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.server = http.server.HTTPServer(('localhost', _PORT), MockHandler)
    threading.Thread(target=self.server.serve_forever).start()

  def tearDown(self):
    super().tearDown()
    if self.server:
      self.server.shutdown()
      self.server.server_close()

  def test_encrypt_decrypt_with_empty_associated_data(self):
    client = hvac.Client(url=_VAULT_URI, token=_TOKEN, verify=False)
    vaultaead = hcvault.new_aead(_KEY_PATH, client)
    plaintext = bytes(i for i in range(256))
    ciphertext = vaultaead.encrypt(plaintext, associated_data=b'')
    self.assertEqual(
        plaintext, vaultaead.decrypt(ciphertext, associated_data=b'')
    )

  def test_encrypt_decrypt_fails_with_nonempty_associated_data(self):
    client = hvac.Client(url=_VAULT_URI, token=_TOKEN, verify=False)
    vaultaead = hcvault.new_aead(_KEY_PATH, client)
    expected_error_msg_re = re.compile(r'.*only allows empty associated data.*')
    with self.assertRaisesRegex(tink.TinkError, expected_error_msg_re):
      _ = vaultaead.encrypt(plaintext=b'hello', associated_data=b'non-empty')
    with self.assertRaisesRegex(tink.TinkError, expected_error_msg_re):
      _ = vaultaead.decrypt(ciphertext=b'hello', associated_data=b'non-empty')

  def test_encrypt_fails_with_unknown_key_name(self):
    client = hvac.Client(url=_VAULT_URI, token=_TOKEN, verify=False)
    vaultaead = hcvault.new_aead('transit/keys/unknown-key', client)
    with self.assertRaises(tink.TinkError):
      _ = vaultaead.encrypt(plaintext=b'plaintext', associated_data=b'')

  def test_decrypt_with_wrong_key_fails(self):
    client = hvac.Client(url=_VAULT_URI, token=_TOKEN, verify=False)
    vaultaead1 = hcvault.new_aead('transit/keys/key-1', client)
    vaultaead2 = hcvault.new_aead('transit/keys/key-2', client)
    plaintext = b'plaintext'
    associated_data = b''
    ciphertext1 = vaultaead1.encrypt(plaintext, associated_data)
    with self.assertRaises(tink.TinkError):
      _ = vaultaead2.decrypt(ciphertext1, associated_data)

  @parameterized.named_parameters([
      ('simple', '/transit/keys/key-1', 'transit', 'key-1'),
      ('simple_no_leading_slash', 'transit/keys/key-1', 'transit', 'key-1'),
      (
          'escaped',
          '/transit/keys/this%2Band+that',
          'transit',
          'this%252Band%2Bthat',
      ),
      (
          'sub_path',
          '/teams/billing/something/transit/keys/pci-key',
          'teams/billing/something/transit',
          'pci-key',
      ),
      (
          'transit_twice',
          '/transit/keys/something/transit/keys/my-key',
          'transit/keys/something/transit',
          'my-key',
      ),
      ('mount_not_named_transit', '/cipher/keys/hi', 'cipher', 'hi'),
  ])
  def test_valid_get_endpoint_paths(
      self, path, expected_mount, expected_key_name
  ):
    mount, path = hcvault._hcvault_kms_aead._get_endpoint_paths(path)
    self.assertEqual(mount, expected_mount)
    self.assertEqual(path, expected_key_name)

  @parameterized.named_parameters([
      ('empty', ''),
      ('slash_only', '/'),
      ('no_mount', '/keys/foo'),
      ('traling_slash', 'mount/keys/foo/'),
      ('invalid_mount', '////keys/foo'),
      ('invalid_mount_and_trailing_slash', '////keys/foo/'),
      ('invalid_mount_with_empty_component_in_between', '/foo//bar/keys/baz'),
      ('invalid_mount_with_empty_trailing_components', '/foo/bar///keys/baz'),
      ('invalid_key_name', '/transit/keys/bar/baz'),
  ])
  def test_invalid_path_raises_error(self, path):
    client = hvac.Client(url=_VAULT_URI, token=_TOKEN, verify=False)
    with self.assertRaises(tink.TinkError):
      hcvault.new_aead(path, client)


if __name__ == '__main__':
  absltest.main()

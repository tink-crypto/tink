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
"""Tests for tink.python.tink.integration.hcvault_kms_client."""

import base64
import http.server
import json
import threading

from absl.testing import absltest
import hvac

import tink
from tink.integration import hcvault

TOKEN = ''  # Your auth token

# Replace this with your vault URI
KEY_URI = 'http://localhost:8200/transit/keys/key-1'

GCP_KEY_URI = (
    'gcp-kms://projects/tink-test-infrastructure/locations/global/'
    'keyRings/unit-and-integration-testing/cryptoKeys/aead-key'
)

VALID_EP_KEY_URIS = {
    'hcvault://localhost:8200/transit/keys/key-1': ['transit', 'key-1'],
    'hcvault://vault.example.com/transit/keys/foo': ['transit', 'foo'],
    'hcvault://vault.example.com/teams/billing/something/transit/keys/pci-key': [
        'teams/billing/something/transit',
        'pci-key',
    ],
    'hcvault://vault.example.com/transit/keys/something/transit/keys/my-key': [
        'transit/keys/something/transit',
        'my-key',
    ],
    'hcvault://vault-prd.example.com/transit/keys/hi': ['transit', 'hi'],
    'hcvault:///transit/keys/hi': ['transit', 'hi'],
    'hcvault:///cipher/keys/hi': ['cipher', 'hi'],
}

INVALID_EP_KEY_URIS = [
    'hcvault://vault.com',
    'hcvault://vault.com/',
    'hcvault://vault.example.com/foo/bar/baz',
    'hcvault://vault.example.com/transit/keys/bar/baz',
]


class MockHandler(http.server.BaseHTTPRequestHandler):

  def do_post(self):
    if 'encrypt' in self.path:
      post_body = self.rfile.read(int(self.headers.get('Content-Length')))
      req = json.loads(post_body)
      ret = self.encrypt(req)
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.end_headers()
      self.wfile.write(ret.encode('utf-8'))
      return

    if 'decrypt' in self.path:
      try:
        post_body = self.rfile.read(int(self.headers.get('Content-Length')))
        req = json.loads(post_body)
        ret = self.decrypt(req)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(ret.encode('utf-8'))
      except (OSError, BlockingIOError):
        self.send_error(400)
      return

    self.send_error(404)

  def do_get(self):
    self.send_error(404)

  def do_put(self):
    self.send_error(404)

  def encrypt(self, data):
    pt64 = data['plaintext']
    context64 = data['context']
    pt = base64.b64decode(pt64)
    context = base64.b64decode(context64)
    resp = {'ciphertext': self._encrypt(pt, context)}
    return json.dumps({'data': resp})

  def decrypt(self, data):
    ct64 = data['ciphertext']
    context64 = data['context']
    context = base64.b64decode(context64)
    resp = {
        'plaintext': base64.b64encode(self._decrypt(ct64, context)).decode()
    }
    return json.dumps({'data': resp})

  def _encrypt(self, plaintext: str, context: str) -> str:
    s = 'enc:%s:%s' % (
        base64.b64encode(context).decode(),
        base64.b64encode(plaintext).decode(),
    )
    return s

  def _decrypt(self, ciphertext: str, context: str) -> bytes:
    parts = ciphertext.split(':')
    if len(parts) != 3 or parts[0] != 'enc':
      raise tink.TinkError('malformed ciphertext')

    context2 = base64.b64decode(parts[1])

    if context != context2:
      raise tink.TinkError("context doesn't match")

    plaintext = base64.b64decode(parts[2])
    return plaintext


class HcVaultKmsAeadTest(absltest.TestCase):
  server = None

  def setUp(self):
    super().setUp()
    print('Running setup')
    self.server = http.server.HTTPServer(('localhost', 8200), MockHandler)
    threading.Thread(target=self.server.serve_forever).start()

  def tearDown(self):
    super().tearDown()
    if self.server:
      self.server.shutdown()
      self.server.server_close()

  def test_encrypt_decrypt(self):
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    vaultaead = hcvault.create_aead(KEY_URI, client)
    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = vaultaead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

  def test_invalid_context(self):
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    vaultaead = hcvault.create_aead(KEY_URI, client)

    plaintext = b'helloworld'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))
    with self.assertRaises(tink.TinkError):
      vaultaead.decrypt(ciphertext, b'a')

  def test_encrypt_with_bad_uri(self):
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    with self.assertRaises(tink.TinkError):
      hcvault.create_aead(GCP_KEY_URI, client)

  def test_endpoint_paths(self):

    for e in VALID_EP_KEY_URIS:
      mount, path = hcvault._hcvault_kms_client._endpoint_paths(e)
      self.assertEqual(mount, VALID_EP_KEY_URIS[e][0])
      self.assertEqual(path, VALID_EP_KEY_URIS[e][1])

    for e in INVALID_EP_KEY_URIS:
      with self.assertRaises(tink.TinkError):
        _, _ = hcvault._hcvault_kms_client._endpoint_paths(e)


if __name__ == '__main__':
  absltest.main()

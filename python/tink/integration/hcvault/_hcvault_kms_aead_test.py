# Copyright 2019 Google LLC
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

from absl.testing import absltest

import tink
from tink.integration import hcvault

from threading import Thread
from flask import Flask, jsonify, request
import requests
import base64
import hvac


TOKEN = "" # Your auth token

KEY_URI = ('https://localhost:8200/transit/keys/key-1') # Replace this with your vault URI

GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')

class MockServer(Thread):
  def __init__(self):
    super().__init__()
    self.app = Flask(__name__)
    self.url = "http://localhost:8200"
    self.app.add_url_rule("/v1/transit/encrypt/key-1", view_func=self.encrypt)
    self.app.add_url_rule("/v1/transit/decrypt/key-1", view_func=self.decrypt)
    self.app.add_url_rule("/shutdown", view_func=self._shutdown_server)


  def _shutdown_server(self):
    from flask import request
    if not 'werkzeug.server.shutdown' in request.environ:
        raise RuntimeError('Not running the development server')
    request.environ['werkzeug.server.shutdown']()
    return 'Server shutting down...'
  
  def shutdown_server(self):
    requests.get("http://localhost:8200/shutdown")
    self.join()

  def _encrypt(self, plaintext: str, context: str) -> bytes:
    s = "enc:%s:%s" % (base64.b64encode(context).decode(), base64.b64encode(plaintext).decode())
    return s.encode()

  def _decrypt(self, ciphertext: str, context: str):
    parts = ciphertext.split(":")
    if len(parts) != 3 or parts[0] != "enc":
      raise Exception("malformed ciphertext")

    context2 = base64.b64decode(parts[1])

    if context != context2: 
      raise Exception("context doesn't match")
    
    plaintext = base64.b64decode(parts[2])
    return plaintext


  def encrypt(self):
    data = request.get_json()
    pt64 = data["plaintext"]
    context64 = data["context"]
    pt = base64.b64decode(pt64)
    context = base64.b64decode(context64)
    resp = {'ciphertext': str(self._encrypt(pt, context))}
    return jsonify(data=resp)

  def decrypt(self):
    data = request.get_json()
    ct64 = data["ciphertext"]
    context64 = data["context"]
    context = base64.b64decode(context64)
    resp = {'ciphertext': str(self._decrypt(ct64, context))}
    return jsonify(data=resp)


class HcVaultKmsAeadTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    server = MockServer()
    server.start()
    yield server
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    vaultaead = hcvault.create_aead(KEY_URI, client)
    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = vaultaead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))
    server.stop()

  def test_corrupted_ciphertext(self):
    server = MockServer()
    server.start()
    yield server
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    vaultaead = hcvault.create_aead(KEY_URI, client)

    plaintext = b'helloworld'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    for byte_idx in [b for b in range(len(ciphertext))]:
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 2
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(corrupted_ciphertext, b'')

    server.stop()

  def test_encrypt_with_bad_uri(self):
    server = MockServer()
    server.start()
    yield server
    client = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
    with self.assertRaises(tink.TinkError):
      hcvault.create_aead(GCP_KEY_URI, client)

    server.stop()

if __name__ == '__main__':
  absltest.main()

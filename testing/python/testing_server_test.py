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

import os
import signal
import subprocess
import time

from typing import Text
from absl import logging
from absl.testing import absltest
import grpc
import portpicker

from tink import aead

from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc


def _server_path() -> Text:
  dir_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.join(dir_path, 'testing_server')


class TestingServerTest(absltest.TestCase):

  _server = None
  _channel = None
  _keyset_stub = None
  _aead_stub = None

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    port = portpicker.pick_unused_port()
    cls._server = subprocess.Popen([
        _server_path(), '-port', '%d' % port,
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logging.info('Server started on port %d with pid: %d.',
                 port, cls._server.pid)
    cls._channel = grpc.secure_channel('[::]:%d' % port,
                                       grpc.local_channel_credentials())
    grpc.channel_ready_future(cls._channel).result()
    cls._keyset_stub = testing_api_pb2_grpc.KeysetStub(cls._channel)
    cls._aead_stub = testing_api_pb2_grpc.AeadStub(cls._channel)

  @classmethod
  def tearDownClass(cls):
    cls._channel.close()
    logging.info('Stopping server...')
    cls._server.send_signal(signal.SIGINT)
    time.sleep(2)
    if cls._server.poll() is None:
      cls._server.kill()
    super().tearDownClass()

  def test_generate_encrypt_decrypt(self):
    t = time.time()
    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.GenerateKeysetRequest(template=template)
    gen_response = self._keyset_stub.Generate(gen_request)
    self.assertEmpty(gen_response.err)
    keyset = gen_response.keyset
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=keyset, plaintext=plaintext, associated_data=associated_data)
    enc_response = self._aead_stub.Encrypt(enc_request)
    self.assertEmpty(enc_response.err)
    ciphertext = enc_response.ciphertext
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = self._aead_stub.Decrypt(dec_request)
    self.assertEmpty(dec_response.err)
    self.assertEqual(dec_response.plaintext, plaintext)
    logging.info('Testing took %s s', time.time() - t)

  def test_generate_decrypt_fail(self):
    template = aead.aead_key_templates.AES128_GCM.SerializeToString()
    gen_request = testing_api_pb2.GenerateKeysetRequest(template=template)
    gen_response = self._keyset_stub.Generate(gen_request)
    self.assertEmpty(gen_response.err)
    keyset = gen_response.keyset

    ciphertext = b'some invalid ciphertext'
    associated_data = b'associated_data'
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=keyset, ciphertext=ciphertext, associated_data=associated_data)
    dec_response = self._aead_stub.Decrypt(dec_request)
    logging.info('Error in response: %s', dec_response.err)
    self.assertNotEmpty(dec_response.err)
    self.assertEmpty(dec_response.plaintext)

if __name__ == '__main__':
  absltest.main()

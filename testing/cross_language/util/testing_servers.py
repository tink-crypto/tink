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
"""testing_server starts up testing gRPC servers in different languages."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
import os
import subprocess
import time

from typing import Text
from absl import logging
import grpc
import portpicker

import tink
from tink import cleartext_keyset_handle
import tink.aead

from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc

# Server paths are relative to os.environ['testing_dir'], which can be set by:
# bazel test util:testing_servers_test --test_env testing_dir=/tmp/tink/testing
# If not set, the testing_dir is calcuated from os.path.abspath(__file__).
_SERVER_PATHS = {
    'cc': [
        'cc/bazel-bin/testing_server',
        'cc/testing_server'
    ],
    'go': [
        'go/bazel-bin/linux_amd64_stripped/testing_server',
        'go/testing_server'
    ],
    'java': [
        'java_src/bazel-bin/testing_server_deploy.jar',
        'java_src/testing_server'
    ],
    'python': [
        'python/bazel-bin/testing_server',
        'python/testing_server',
    ]
}

# All languages that have an testing server
LANGUAGES = list(_SERVER_PATHS.keys())


def _server_path(lang: Text) -> Text:
  """Returns the path where the server binary is located."""
  if os.environ.get('testing_dir'):
    testing_dir = os.environ.get('testing_dir')
  else:
    util_dir = os.path.dirname(os.path.abspath(__file__))
    testing_dir = os.path.dirname(os.path.dirname(util_dir))
  for relative_server_path in _SERVER_PATHS[lang]:
    server_path = os.path.join(testing_dir, relative_server_path)
    logging.info('try path: %s', server_path)
    if os.path.exists(server_path):
      return server_path
  raise RuntimeError('Executable for lang %s not found' % lang)


def _keyset(keyset_handle: tink.KeysetHandle) -> bytes:
  """Returns the keyset contained in the keyset_handle."""
  keyset_buffer = io.BytesIO()
  cleartext_keyset_handle.write(
      tink.BinaryKeysetWriter(keyset_buffer), keyset_handle)
  return keyset_buffer.getvalue()


def _new_keyset_handle(stub: testing_api_pb2_grpc.KeysetStub,
                       key_template: tink_pb2.KeyTemplate) -> tink.KeysetHandle:
  gen_request = testing_api_pb2.GenerateKeysetRequest(
      template=key_template.SerializeToString())
  gen_response = stub.Generate(gen_request)
  if gen_response.err:
    raise tink.TinkError(gen_response.err)
  return cleartext_keyset_handle.read(
      tink.BinaryKeysetReader(gen_response.keyset))


class _Aead(tink.aead.Aead):
  """Wraps AEAD services stub into an Aead primitive."""

  def __init__(self,
               lang: Text,
               stub: testing_api_pb2_grpc.AeadStub,
               keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._stub = stub
    self._keyset_handle = keyset_handle

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    logging.info('encrypt in lang %s.', self.lang)
    enc_request = testing_api_pb2.AeadEncryptRequest(
        keyset=_keyset(self._keyset_handle),
        plaintext=plaintext,
        associated_data=associated_data)
    enc_response = self._stub.Encrypt(enc_request)
    if enc_response.err:
      logging.info('error encrypt in %s: %s', self.lang, enc_response.err)
      raise tink.TinkError(enc_response.err)
    return enc_response.ciphertext

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    logging.info('decrypt in lang %s.', self.lang)
    dec_request = testing_api_pb2.AeadDecryptRequest(
        keyset=_keyset(self._keyset_handle),
        ciphertext=ciphertext, associated_data=associated_data)
    dec_response = self._stub.Decrypt(dec_request)
    if dec_response.err:
      logging.info('error decrypt in %s: %s', self.lang, dec_response.err)
      raise tink.TinkError(dec_response.err)
    return dec_response.plaintext


class _TestingServers():
  """TestingServers starts up testing gRPC servers and returns service stubs."""

  def __init__(self):
    self._server = {}
    self._channel = {}
    self._metadata_stub = {}
    self._keyset_stub = {}
    self._aead_stub = {}
    for lang in LANGUAGES:
      port = portpicker.pick_unused_port()
      cmd = [_server_path(lang), '--port', '%d' % port]
      logging.info('cmd = %s', cmd)
      self._server[lang] = subprocess.Popen(
          cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      logging.info('%s server started on port %d with pid: %d.',
                   lang, port, self._server[lang].pid)
      self._channel[lang] = grpc.secure_channel(
          '[::]:%d' % port, grpc.local_channel_credentials())
    for lang in LANGUAGES:
      try:
        grpc.channel_ready_future(self._channel[lang]).result(timeout=30)
      except:
        logging.info('Timeout while connecting to server %s', lang)
        self._server[lang].kill()
        out, err = self._server[lang].communicate()
        raise RuntimeError(
            'Could not start %s server, output=%s, err=%s' % (lang, out, err))
      self._metadata_stub[lang] = testing_api_pb2_grpc.MetadataStub(
          self._channel[lang])
      self._keyset_stub[lang] = testing_api_pb2_grpc.KeysetStub(
          self._channel[lang])
      self._aead_stub[lang] = testing_api_pb2_grpc.AeadStub(
          self._channel[lang])

  def keyset_stub(self, lang) -> testing_api_pb2_grpc.KeysetStub:
    return self._keyset_stub[lang]

  def aead_stub(self, lang) -> testing_api_pb2_grpc.AeadStub:
    return self._aead_stub[lang]

  def metadata_stub(self, lang) -> testing_api_pb2_grpc.MetadataStub:
    return self._metadata_stub[lang]

  def stop(self):
    """Stops all servers."""
    logging.info('Stopping servers...')
    for lang in LANGUAGES:
      self._channel[lang].close()
    for lang in LANGUAGES:
      self._server[lang].terminate()
    time.sleep(2)
    for lang in LANGUAGES:
      if self._server[lang].poll() is None:
        logging.info('Killing server %s.', lang)
        self._server[lang].kill()
    logging.info('All servers stopped.')


_ts = None


def start() -> None:
  """Starts all servers."""
  global _ts
  _ts = _TestingServers()

  for lang in LANGUAGES:
    response = _ts.metadata_stub(lang).GetServerInfo(
        testing_api_pb2.ServerInfoRequest())
    if lang != response.language:
      raise ValueError(
          'lang = %s != response.language = %s' % (lang, response.language))
    logging.info('server_info:\n%s', response)


def stop() -> None:
  """Stops all servers."""
  global _ts
  _ts.stop()


def new_keyset_handle(
    lang: Text, key_template: tink_pb2.KeyTemplate) -> tink.KeysetHandle:
  """Returns a new KeysetHandle, implemented in lang."""
  global _ts
  return _new_keyset_handle(_ts.keyset_stub(lang), key_template)


def aead(lang: Text, keyset_handle: tink.KeysetHandle) -> _Aead:
  """Returns an AEAD primitive, implemented in lang."""
  global _ts
  return _Aead(lang, _ts.aead_stub(lang), keyset_handle)

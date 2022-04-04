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
"""testing_server starts up testing gRPC servers in different languages."""

import os
import subprocess
import time

from typing import List, Optional
from absl import logging
import grpc
import portpicker

from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc
from tink.testing import helper
from util import _primitives

# Server paths are relative to tink_root_path(), which can be set manually by:
# bazel test util:testing_servers_test --test_env TINK_SRC_PATH=/tmp/tink
_SERVER_PATHS = {
    'cc': [
        'testing/cc/bazel-bin/testing_server',
        'testing/cc/testing_server'
    ],
    'go': [
        'testing/go/bazel-bin/testing_server_/testing_server',
        'testing/go/testing_server'
    ],
    'java': [
        'testing/java_src/bazel-bin/testing_server_deploy.jar',
        'testing/java_src/testing_server'
    ],
    'python': [
        'testing/python/bazel-bin/testing_server',
        'testing/python/testing_server',
    ]
}

# All languages that have a testing server
LANGUAGES = list(_SERVER_PATHS.keys())

KEYSET_READER_WRITER_TYPES = [('KEYSET_READER_BINARY', 'KEYSET_WRITER_BINARY'),
                              ('KEYSET_READER_JSON', 'KEYSET_WRITER_JSON')]

# location of the testing_server java binary, relative to tink_root_path()
_JAVA_PATH = (
    'testing/java_src/bazel-bin/testing_server.runfiles/local_jdk/bin/java')

_PRIMITIVE_STUBS = {
    'aead': testing_api_pb2_grpc.AeadStub,
    'daead': testing_api_pb2_grpc.DeterministicAeadStub,
    'streaming_aead': testing_api_pb2_grpc.StreamingAeadStub,
    'hybrid': testing_api_pb2_grpc.HybridStub,
    'mac': testing_api_pb2_grpc.MacStub,
    'signature': testing_api_pb2_grpc.SignatureStub,
    'prf': testing_api_pb2_grpc.PrfSetStub,
    'jwt': testing_api_pb2_grpc.JwtStub,
}

# All primitives.
_PRIMITIVES = list(_PRIMITIVE_STUBS.keys())

SUPPORTED_LANGUAGES_BY_PRIMITIVE = {
    'aead': ['cc', 'go', 'java', 'python'],
    'daead': ['cc', 'go', 'java', 'python'],
    'streaming_aead': ['cc', 'go', 'java', 'python'],
    'hybrid': ['cc', 'go', 'java', 'python'],
    'mac': ['cc', 'go', 'java', 'python'],
    'signature': ['cc', 'go', 'java', 'python'],
    'prf': ['cc', 'java', 'go', 'python'],
    'jwt': ['cc', 'java', 'go', 'python'],
}


def _server_path(lang: str) -> str:
  """Returns the path where the server binary is located."""
  root_dir = helper.tink_root_path()
  for relative_server_path in _SERVER_PATHS[lang]:
    server_path = os.path.join(root_dir, relative_server_path)
    logging.info('try path: %s', server_path)
    if os.path.exists(server_path):
      return server_path
  raise RuntimeError('Executable for lang %s not found' % lang)


def _server_cmd(lang: str, port: int) -> List[str]:
  server_path = _server_path(lang)
  if lang == 'java' and server_path.endswith('.jar'):
    java_path = os.path.join(helper.tink_root_path(), _JAVA_PATH)
    return [java_path, '-jar', server_path, '--port', '%d' % port]
  else:
    return [server_path, '--port', '%d' % port]


class _TestingServers():
  """TestingServers starts up testing gRPC servers and returns service stubs."""

  def __init__(self, test_name: str):
    self._server = {}
    self._output_file = {}
    self._channel = {}
    self._metadata_stub = {}
    self._keyset_stub = {}
    self._aead_stub = {}
    self._daead_stub = {}
    self._streaming_aead_stub = {}
    self._hybrid_stub = {}
    self._mac_stub = {}
    self._signature_stub = {}
    self._prf_stub = {}
    self._jwt_stub = {}
    for lang in LANGUAGES:
      port = portpicker.pick_unused_port()
      cmd = _server_cmd(lang, port)
      logging.info('cmd = %s', cmd)
      try:
        output_dir = os.environ['TEST_UNDECLARED_OUTPUTS_DIR']
      except KeyError as e:
        raise RuntimeError(
            'Could not start %s server, TEST_UNDECLARED_OUTPUTS_DIR environment'
            'variable must be set') from e
      output_file = '%s-%s-%s' % (test_name, lang, 'server.log')
      output_path = os.path.join(output_dir, output_file)
      logging.info('writing server output to %s', output_path)
      try:
        self._output_file[lang] = open(output_path, 'w+')
      except IOError as e:
        logging.info('unable to open server output file %s', output_path)
        raise RuntimeError('Could not start %s server' % lang) from e
      self._server[lang] = subprocess.Popen(
          cmd, stdout=self._output_file[lang], stderr=subprocess.STDOUT)
      logging.info('%s server started on port %d with pid: %d.',
                   lang, port, self._server[lang].pid)
      self._channel[lang] = grpc.secure_channel(
          '[::]:%d' % port, grpc.local_channel_credentials())
    for lang in LANGUAGES:
      try:
        grpc.channel_ready_future(self._channel[lang]).result(timeout=30)
      except Exception as e:
        logging.info('Timeout while connecting to server %s', lang)
        self._server[lang].kill()
        out, err = self._server[lang].communicate()
        raise RuntimeError('Could not start %s server, output=%s, err=%s' %
                           (lang, out, err)) from e
      self._metadata_stub[lang] = testing_api_pb2_grpc.MetadataStub(
          self._channel[lang])
      self._keyset_stub[lang] = testing_api_pb2_grpc.KeysetStub(
          self._channel[lang])
    for primitive in _PRIMITIVES:
      for lang in SUPPORTED_LANGUAGES_BY_PRIMITIVE[primitive]:
        stub_name = '_%s_stub' % primitive
        getattr(self, stub_name)[lang] = _PRIMITIVE_STUBS[primitive](
            self._channel[lang])

  def keyset_stub(self, lang) -> testing_api_pb2_grpc.KeysetStub:
    return self._keyset_stub[lang]

  def aead_stub(self, lang) -> testing_api_pb2_grpc.AeadStub:
    return self._aead_stub[lang]

  def daead_stub(self, lang) -> testing_api_pb2_grpc.DeterministicAeadStub:
    return self._daead_stub[lang]

  def streaming_aead_stub(self, lang) -> testing_api_pb2_grpc.StreamingAeadStub:
    return self._streaming_aead_stub[lang]

  def hybrid_stub(self, lang) -> testing_api_pb2_grpc.HybridStub:
    return self._hybrid_stub[lang]

  def mac_stub(self, lang) -> testing_api_pb2_grpc.MacStub:
    return self._mac_stub[lang]

  def signature_stub(self, lang) -> testing_api_pb2_grpc.SignatureStub:
    return self._signature_stub[lang]

  def prf_stub(self, lang) -> testing_api_pb2_grpc.PrfSetStub:
    return self._prf_stub[lang]

  def jwt_stub(self, lang) -> testing_api_pb2_grpc.JwtStub:
    return self._jwt_stub[lang]

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
    for lang in LANGUAGES:
      self._output_file[lang].close()
    logging.info('All servers stopped.')


_ts = None


def start(output_files_prefix: str) -> None:
  """Starts all servers."""
  global _ts
  _ts = _TestingServers(output_files_prefix)

  versions = {}
  for lang in LANGUAGES:
    response = _ts.metadata_stub(lang).GetServerInfo(
        testing_api_pb2.ServerInfoRequest())
    if lang != response.language:
      raise ValueError(
          'lang = %s != response.language = %s' % (lang, response.language))
    if response.tink_version:
      versions[lang] = response.tink_version
    else:
      logging.warning('server in lang %s has no tink version.', lang)
  unique_versions = list(set(versions.values()))
  if not unique_versions:
    raise ValueError('tink version unknown')
  if len(unique_versions) > 1:
    raise ValueError('tink_version in testing servers are inconsistent: %s' %
                     versions)
  logging.info('Tink version: %s', unique_versions[0])


def stop() -> None:
  """Stops all servers."""
  global _ts
  _ts.stop()


def key_template(lang: str, template_name: str) -> tink_pb2.KeyTemplate:
  """Returns the key template of template_name, implemented in lang."""
  global _ts
  return _primitives.key_template(_ts.keyset_stub(lang), template_name)


def new_keyset(lang: str, template: tink_pb2.KeyTemplate) -> bytes:
  """Returns a new KeysetHandle, implemented in lang."""
  global _ts
  return _primitives.new_keyset(_ts.keyset_stub(lang), template)


def public_keyset(lang: str, private_keyset: bytes) -> bytes:
  """Returns a public keyset handle, implemented in lang."""
  global _ts
  return _primitives.public_keyset(_ts.keyset_stub(lang), private_keyset)


def keyset_to_json(lang: str, keyset: bytes) -> str:
  global _ts
  return _primitives.keyset_to_json(_ts.keyset_stub(lang), keyset)


def keyset_from_json(lang: str, json_keyset: str) -> bytes:
  global _ts
  return _primitives.keyset_from_json(_ts.keyset_stub(lang), json_keyset)


def keyset_read_encrypted(lang: str, encrypted_keyset: bytes,
                          master_keyset: bytes,
                          associated_data: Optional[bytes],
                          keyset_reader_type: str) -> bytes:
  global _ts
  return _primitives.keyset_read_encrypted(
      _ts.keyset_stub(lang), encrypted_keyset, master_keyset, associated_data,
      keyset_reader_type)


def keyset_write_encrypted(lang: str, keyset: bytes, master_keyset: bytes,
                           associated_data: Optional[bytes],
                           keyset_writer_type: str) -> bytes:
  global _ts
  return _primitives.keyset_write_encrypted(
      _ts.keyset_stub(lang), keyset, master_keyset, associated_data,
      keyset_writer_type)


def jwk_set_to_keyset(lang: str, jwk_set: str) -> bytes:
  global _ts
  return _primitives.jwk_set_to_keyset(_ts.jwt_stub(lang), jwk_set)


def jwk_set_from_keyset(lang: str, keyset: bytes) -> str:
  global _ts
  return _primitives.jwk_set_from_keyset(_ts.jwt_stub(lang), keyset)


def aead(lang: str, keyset: bytes) -> _primitives.Aead:
  """Returns an AEAD primitive, implemented in lang."""
  global _ts
  return _primitives.Aead(lang, _ts.aead_stub(lang), keyset)


def deterministic_aead(lang: str,
                       keyset: bytes) -> _primitives.DeterministicAead:
  """Returns a DeterministicAEAD primitive, implemented in lang."""
  global _ts
  return _primitives.DeterministicAead(lang, _ts.daead_stub(lang), keyset)


def streaming_aead(lang: str, key_handle: bytes) -> _primitives.StreamingAead:
  """Returns a StreamingAEAD primitive, implemented in lang."""
  global _ts
  return _primitives.StreamingAead(
      lang, _ts.streaming_aead_stub(lang), key_handle)


def hybrid_encrypt(lang: str, pub_keyset: bytes) -> _primitives.HybridEncrypt:
  """Returns a HybridEncrypt  primitive, implemented in lang."""
  global _ts
  return _primitives.HybridEncrypt(lang, _ts.hybrid_stub(lang), pub_keyset)


def hybrid_decrypt(lang: str, priv_keyset: bytes) -> _primitives.HybridDecrypt:
  """Returns a HybridDecrypt primitive, implemented in lang."""
  global _ts
  return _primitives.HybridDecrypt(lang, _ts.hybrid_stub(lang), priv_keyset)


def mac(lang: str, keyset: bytes) -> _primitives.Mac:
  """Returns a MAC primitive, implemented in lang."""
  global _ts
  return _primitives.Mac(lang, _ts.mac_stub(lang), keyset)


def public_key_sign(lang: str,
                    priv_keyset: bytes) -> _primitives.PublicKeySign:
  """Returns an PublicKeySign primitive, implemented in lang."""
  global _ts
  return _primitives.PublicKeySign(lang, _ts.signature_stub(lang), priv_keyset)


def public_key_verify(lang: str,
                      pub_keyset: bytes) -> _primitives.PublicKeyVerify:
  """Returns an PublicKeyVerify primitive, implemented in lang."""
  global _ts
  return _primitives.PublicKeyVerify(lang, _ts.signature_stub(lang), pub_keyset)


def prf_set(lang: str, keyset: bytes) -> _primitives.PrfSet:
  """Returns an PrfSet primitive, implemented in lang."""
  global _ts
  return _primitives.PrfSet(lang, _ts.prf_stub(lang), keyset)


def jwt_mac(lang: str, keyset: bytes) -> _primitives.JwtMac:
  """Returns a JwtMac primitive, implemented in lang."""
  global _ts
  return _primitives.JwtMac(lang, _ts.jwt_stub(lang), keyset)


def jwt_public_key_sign(lang: str,
                        keyset: bytes) -> _primitives.JwtPublicKeySign:
  """Returns a JwtPublicKeySign primitive, implemented in lang."""
  global _ts
  return _primitives.JwtPublicKeySign(lang, _ts.jwt_stub(lang), keyset)


def jwt_public_key_verify(lang: str,
                          keyset: bytes) -> _primitives.JwtPublicKeyVerify:
  """Returns a JwtPublicKeyVerify primitive, implemented in lang."""
  global _ts
  return _primitives.JwtPublicKeyVerify(lang, _ts.jwt_stub(lang), keyset)

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
"""Tink Primitive Testing Service in Python."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from concurrent import futures
import io

from absl import app
from absl import flags
import grpc
import tink
from tink import aead
from tink import cleartext_keyset_handle
from tink.proto import tink_pb2
from proto.testing import testing_api_pb2
from proto.testing import testing_api_pb2_grpc

FLAGS = flags.FLAGS

flags.DEFINE_integer('port', 10000, 'The port of the server.')


class MetadataServicer(testing_api_pb2_grpc.MetadataServicer):
  """A service with metadata about the server."""

  def GetServerInfo(
      self, request: testing_api_pb2.ServerInfoRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.ServerInfo:
    """Generates a keyset."""
    return testing_api_pb2.ServerInfo(language='python')


class KeysetServicer(testing_api_pb2_grpc.KeysetServicer):
  """A service for testing Keyset operations."""

  def Generate(
      self, request: testing_api_pb2.GenerateKeysetRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.KeysetResponse:
    """Generates a keyset."""
    try:
      template = tink_pb2.KeyTemplate()
      template.ParseFromString(request.template)
      keyset_handle = tink.new_keyset_handle(template)
      keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(keyset), keyset_handle)
      return testing_api_pb2.KeysetResponse(keyset=keyset.getvalue())
    except tink.TinkError as e:
      return testing_api_pb2.KeysetResponse(err=str(e))


class AeadServicer(testing_api_pb2_grpc.AeadServicer):
  """A service for testing Aead encryption."""

  def Encrypt(
      self, request: testing_api_pb2.AeadEncryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.CiphertextResponse:
    """Encrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      ciphertext = p.encrypt(request.plaintext, request.associated_data)
      return testing_api_pb2.CiphertextResponse(ciphertext=ciphertext)
    except tink.TinkError as e:
      return testing_api_pb2.CiphertextResponse(err=str(e))

  def Decrypt(
      self, request: testing_api_pb2.AeadDecryptRequest,
      context: grpc.ServicerContext) -> testing_api_pb2.PlaintextResponse:
    """Decrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      plaintext = p.decrypt(request.ciphertext, request.associated_data)
      return testing_api_pb2.PlaintextResponse(plaintext=plaintext)
    except tink.TinkError as e:
      return testing_api_pb2.PlaintextResponse(err=str(e))


def main(unused_argv):
  aead.register()
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
  testing_api_pb2_grpc.add_MetadataServicer_to_server(
      MetadataServicer(), server)
  testing_api_pb2_grpc.add_KeysetServicer_to_server(KeysetServicer(), server)
  testing_api_pb2_grpc.add_AeadServicer_to_server(AeadServicer(), server)
  server.add_secure_port('[::]:%d' % FLAGS.port,
                         grpc.local_server_credentials())
  server.start()
  server.wait_for_termination()


if __name__ == '__main__':
  app.run(main)

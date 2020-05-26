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
from tools.testing import tink_testing_pb2
from tools.testing import tink_testing_pb2_grpc
from google3.net.grpc.python import loas2
from tink.proto import tink_pb2

FLAGS = flags.FLAGS

flags.DEFINE_integer('port', 10000, 'The port of the server.')


class TinkTestingServicer(tink_testing_pb2_grpc.TinkTestingServicer):
  """A Tink Primitive Testing gRPC server."""

  def GenerateKeyset(
      self, request: tink_testing_pb2.GenerateKeysetRequest,
      context: grpc.ServicerContext) -> tink_testing_pb2.GenerateKeysetResponse:
    """Generates a keyset."""
    try:
      template = tink_pb2.KeyTemplate()
      template.ParseFromString(request.template)
      keyset_handle = tink.new_keyset_handle(template)
      keyset = io.BytesIO()
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(keyset), keyset_handle)
      return tink_testing_pb2.GenerateKeysetResponse(keyset=keyset.getvalue())
    except tink.TinkError as e:
      return tink_testing_pb2.GenerateKeysetResponse(err=str(e))

  def AeadEncrypt(
      self, request: tink_testing_pb2.AeadEncryptRequest,
      context: grpc.ServicerContext) -> tink_testing_pb2.AeadEncryptResponse:
    """Encrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      ciphertext = p.encrypt(request.plaintext, request.associated_data)
      return tink_testing_pb2.AeadEncryptResponse(ciphertext=ciphertext)
    except tink.TinkError as e:
      return tink_testing_pb2.AeadEncryptResponse(err=str(e))

  def AeadDecrypt(
      self, request: tink_testing_pb2.AeadDecryptRequest,
      context: grpc.ServicerContext) -> tink_testing_pb2.AeadDecryptResponse:
    """Decrypts a message."""
    try:
      keyset_handle = cleartext_keyset_handle.read(
          tink.BinaryKeysetReader(request.keyset))
      p = keyset_handle.primitive(aead.Aead)
      plaintext = p.decrypt(request.ciphertext, request.associated_data)
      return tink_testing_pb2.AeadDecryptResponse(plaintext=plaintext)
    except tink.TinkError as e:
      return tink_testing_pb2.AeadDecryptResponse(err=str(e))


def main(unused_argv):
  aead.register()
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
  servicer = TinkTestingServicer()
  tink_testing_pb2_grpc.add_TinkTestingServicer_to_server(servicer, server)
  server.add_secure_port('[::]:%d' % FLAGS.port,
                         loas2.loas2_server_credentials())
  server.start()
  server.wait_for_termination()


if __name__ == '__main__':
  app.run(main)

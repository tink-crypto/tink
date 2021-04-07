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

from absl import app
from absl import flags
import grpc
from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from proto.testing import testing_api_pb2_grpc

from tink import jwt
from tink.testing import fake_kms

import jwt_service
import services

FLAGS = flags.FLAGS

flags.DEFINE_integer('port', 10000, 'The port of the server.')


def main(unused_argv):
  aead.register()
  daead.register()
  hybrid.register()
  mac.register()
  prf.register()
  signature.register()
  streaming_aead.register()
  jwt.register_jwt_mac()
  fake_kms.register_client()
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
  testing_api_pb2_grpc.add_MetadataServicer_to_server(
      services.MetadataServicer(), server)
  testing_api_pb2_grpc.add_KeysetServicer_to_server(
      services.KeysetServicer(), server)
  testing_api_pb2_grpc.add_AeadServicer_to_server(
      services.AeadServicer(), server)
  testing_api_pb2_grpc.add_DeterministicAeadServicer_to_server(
      services.DeterministicAeadServicer(), server)
  testing_api_pb2_grpc.add_MacServicer_to_server(
      services.MacServicer(), server)
  testing_api_pb2_grpc.add_PrfSetServicer_to_server(services.PrfSetServicer(),
                                                    server)
  testing_api_pb2_grpc.add_HybridServicer_to_server(
      services.HybridServicer(), server)
  testing_api_pb2_grpc.add_SignatureServicer_to_server(
      services.SignatureServicer(), server)
  testing_api_pb2_grpc.add_StreamingAeadServicer_to_server(
      services.StreamingAeadServicer(), server)
  testing_api_pb2_grpc.add_JwtServicer_to_server(jwt_service.JwtServicer(),
                                                 server)
  server.add_secure_port('[::]:%d' % FLAGS.port,
                         grpc.local_server_credentials())
  server.start()
  server.wait_for_termination()


if __name__ == '__main__':
  app.run(main)

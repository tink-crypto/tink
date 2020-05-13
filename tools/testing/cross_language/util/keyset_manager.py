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
"""Python implementation of a KeysetManager."""

# Placeholder for import for type annotations

import tink
from tink.proto import tink_pb2
from tools.testing.cross_language.util import cli_tinkey


_CHACHA20_POLY1305_KEY_TYPES = (
    'type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key')


def new_keyset_handle(key_template: tink_pb2.KeyTemplate) -> tink.KeysetHandle:
  if key_template.type_url == _CHACHA20_POLY1305_KEY_TYPES:
    return cli_tinkey.generate_keyset_handle('CHACHA20_POLY1305')
  return tink.new_keyset_handle(key_template)

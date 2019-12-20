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
"""Python wrapper of the CLIF-wrapped C++ Streaming AEAD key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import typing
from typing import Text, BinaryIO

from tink.python.cc.clif import cc_key_manager
from tink.python.core import key_manager
from tink.python.core import tink_error
from tink.python.streaming_aead import decrypting_stream
from tink.python.streaming_aead import encrypting_stream
from tink.python.streaming_aead import streaming_aead


class _StreamingAeadCcToPyWrapper(streaming_aead.StreamingAead):
  """Transforms cliffed C++ StreamingAead into a Python primitive."""

  def __init__(self, cc_streaming_aead):
    self._streaming_aead = cc_streaming_aead

  @tink_error.use_tink_errors
  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    stream = encrypting_stream.EncryptingStream(self._streaming_aead,
                                                ciphertext_destination,
                                                associated_data)
    return typing.cast(BinaryIO, stream)

  @tink_error.use_tink_errors
  def new_decrypting_stream(self, ciphertext_source: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    stream = decrypting_stream.DecryptingStream(self._streaming_aead,
                                                ciphertext_source,
                                                associated_data)
    return typing.cast(BinaryIO, stream)


def from_cc_registry(
    type_url: Text) -> key_manager.KeyManager[streaming_aead.StreamingAead]:
  return key_manager.KeyManagerCcToPyWrapper(
      cc_key_manager.StreamingAeadKeyManager.from_cc_registry(type_url),
      streaming_aead.StreamingAead, _StreamingAeadCcToPyWrapper)

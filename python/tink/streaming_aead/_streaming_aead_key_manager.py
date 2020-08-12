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
"""Python wrapper of the wrapped C++ Streaming AEAD key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
import typing
from typing import Text, BinaryIO
import six

from tink import core
from tink.cc.pybind import tink_bindings
from tink.streaming_aead import _decrypting_stream
from tink.streaming_aead import _encrypting_stream
from tink.streaming_aead import _streaming_aead


class _StreamingAeadCcToPyWrapper(_streaming_aead.StreamingAead):
  """Transforms C++ StreamingAead into a Python primitive."""

  def __init__(self, cc_streaming_aead: tink_bindings.StreamingAead):
    self._cc_streaming_aead = cc_streaming_aead

  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    raw = _encrypting_stream.RawEncryptingStream(self._cc_streaming_aead,
                                                 ciphertext_destination,
                                                 associated_data)
    return typing.cast(BinaryIO, io.BufferedWriter(raw))

  def new_decrypting_stream(self, ciphertext_source: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    raw = _decrypting_stream.RawDecryptingStream(self._cc_streaming_aead,
                                                 ciphertext_source,
                                                 associated_data)
    return typing.cast(BinaryIO, io.BufferedReader(raw))


def from_cc_registry(
    type_url: Text) -> core.KeyManager[_streaming_aead.StreamingAead]:
  return core.KeyManagerCcToPyWrapper(
      tink_bindings.StreamingAeadKeyManager.from_cc_registry(type_url),
      _streaming_aead.StreamingAead, _StreamingAeadCcToPyWrapper)


def register() -> None:
  """Registers all AEAD key managers and AEAD wrapper in the Registry."""
  if six.PY2:
    raise NotImplementedError('StreamingAEAD requires Python 3.')
  tink_bindings.register()
  for ident in (
      'AesCtrHmacStreamingKey',
      'AesGcmHkdfStreamingKey',
  ):
    type_url = 'type.googleapis.com/google.crypto.tink.{}'.format(ident)
    key_manager = core.KeyManagerCcToPyWrapper(
        tink_bindings.StreamingAeadKeyManager.from_cc_registry(type_url),
        _streaming_aead.StreamingAead, _StreamingAeadCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)

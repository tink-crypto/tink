# Copyright 2020 Google LLC
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
"""Python wrapper of the wrapped C++ Streaming AEAD key manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import Text, BinaryIO
import six

from tink import core
from tink.cc.pybind import tink_bindings
from tink.streaming_aead import _decrypting_stream
from tink.streaming_aead import _encrypting_stream
from tink.streaming_aead import _raw_streaming_aead
from tink.streaming_aead import _streaming_aead_wrapper


class _StreamingAeadCcToPyWrapper(_raw_streaming_aead.RawStreamingAead):
  """Transforms C++ StreamingAead into a RawStreamingAead Python primitive."""

  def __init__(self, cc_streaming_aead: tink_bindings.StreamingAead):
    self._cc_streaming_aead = cc_streaming_aead

  def new_raw_encrypting_stream(self, ciphertext_destination: BinaryIO,
                                associated_data: bytes) -> io.RawIOBase:
    return _encrypting_stream.RawEncryptingStream(self._cc_streaming_aead,
                                                  ciphertext_destination,
                                                  associated_data)

  def new_raw_decrypting_stream(
      self,
      ciphertext_source: BinaryIO,
      associated_data: bytes,
      close_ciphertext_source: bool) -> io.RawIOBase:
    return _decrypting_stream.RawDecryptingStream(
        self._cc_streaming_aead,
        ciphertext_source,
        associated_data,
        close_ciphertext_source=close_ciphertext_source)


def from_cc_registry(
    type_url: Text) -> core.KeyManager[_raw_streaming_aead.RawStreamingAead]:
  return core.KeyManagerCcToPyWrapper(
      tink_bindings.StreamingAeadKeyManager.from_cc_registry(type_url),
      _raw_streaming_aead.RawStreamingAead, _StreamingAeadCcToPyWrapper)


def register() -> None:
  """Registers Streaming AEAD key managers and the wrapper in the Registry."""
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
        _raw_streaming_aead.RawStreamingAead, _StreamingAeadCcToPyWrapper)
    core.Registry.register_key_manager(key_manager, new_key_allowed=True)
  core.Registry.register_primitive_wrapper(
      _streaming_aead_wrapper.StreamingAeadWrapper())

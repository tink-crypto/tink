# Copyright 2019 Google LLC.
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

"""This class implements helper functions for testing."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text

from tink.proto import tink_pb2
from tink.python import aead
from tink.python import daead
from tink.python import hybrid
from tink.python import mac
from tink.python import signature as pk_signature
from tink.python.core import tink_error


def fake_key(value: bytes = b'fakevalue',
             type_url: Text = 'fakeurl',
             key_material_type: tink_pb2.KeyData.KeyMaterialType = tink_pb2
             .KeyData.SYMMETRIC,
             key_id: int = 1234,
             status: tink_pb2.KeyStatusType = tink_pb2.ENABLED,
             output_prefix_type: tink_pb2.OutputPrefixType = tink_pb2.TINK
            ) -> tink_pb2.Keyset.Key:
  """Returns a fake but valid key."""
  key = tink_pb2.Keyset.Key(
      key_id=key_id,
      status=status,
      output_prefix_type=output_prefix_type)
  key.key_data.type_url = type_url
  key.key_data.value = value
  key.key_data.key_material_type = key_material_type
  return key


class FakeMac(mac.Mac):
  """A fake MAC implementation."""

  def __init__(self, name: Text = 'FakeMac'):
    self._name = name

  def compute_mac(self, data: bytes) -> bytes:
    return data + b'|' + self._name.encode()

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    if mac_value != data + b'|' + self._name.encode():
      raise tink_error.TinkError('invalid mac ' + mac_value.decode())


class FakeAead(aead.Aead):
  """A fake AEAD implementation."""

  def __init__(self, name: Text = 'FakeAead'):
    self._name = name

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    return plaintext + b'|' + associated_data + b'|' + self._name.encode()

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    data = ciphertext.split(b'|')
    if (len(data) < 3 or data[1] != associated_data or
        data[2] != self._name.encode()):
      raise tink_error.TinkError('failed to decrypt ciphertext ' +
                                 ciphertext.decode())
    return data[0]


class FakeDeterministicAead(daead.DeterministicAead):
  """A fake Deterministic AEAD implementation."""

  def __init__(self, name: Text = 'FakeDeterministicAead'):
    self._name = name

  def encrypt_deterministically(self, plaintext: bytes,
                                associated_data: bytes) -> bytes:
    return plaintext + b'|' + associated_data + b'|' + self._name.encode()

  def decrypt_deterministically(self, ciphertext: bytes,
                                associated_data: bytes) -> bytes:
    data = ciphertext.split(b'|')
    if (len(data) < 3 or
        data[1] != associated_data or
        data[2] != self._name.encode()):
      raise tink_error.TinkError('failed to decrypt ciphertext ' +
                                 ciphertext.decode())
    return data[0]


class FakeHybridDecrypt(hybrid.HybridDecrypt):
  """A fake HybridEncrypt implementation."""

  def __init__(self, name: Text = 'Hybrid'):
    self._name = name

  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    data = ciphertext.split(b'|')
    if (len(data) < 3 or
        data[1] != context_info or
        data[2] != self._name.encode()):
      raise tink_error.TinkError('failed to decrypt ciphertext ' +
                                 ciphertext.decode())
    return data[0]


class FakeHybridEncrypt(hybrid.HybridEncrypt):
  """A fake HybridEncrypt implementation."""

  def __init__(self, name: Text = 'Hybrid'):
    self._name = name

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    return plaintext + b'|' + context_info + b'|' + self._name.encode()


class FakePublicKeySign(pk_signature.PublicKeySign):
  """A fake PublicKeySign implementation."""

  def __init__(self, name: Text = 'FakePublicKeySign'):
    self._name = name

  def sign(self, data: bytes) -> bytes:
    return data + b'|' + self._name.encode()


class FakePublicKeyVerify(pk_signature.PublicKeyVerify):
  """A fake PublicKeyVerify implementation."""

  def __init__(self, name: Text = 'FakePublicKeyVerify'):
    self._name = name

  def verify(self, signature: bytes, data: bytes):
    if signature != data + b'|' + self._name.encode():
      raise tink_error.TinkError('invalid signature ' + signature.decode())

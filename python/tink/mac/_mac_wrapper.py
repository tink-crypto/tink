# Copyright 2020 Google LLC.
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
"""MAC wrapper.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Type
from absl import logging


from tink.proto import tink_pb2
from tink import core
from tink.mac import _mac


class _WrappedMac(_mac.Mac):
  """Implements Mac for a set of Mac primitives."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def compute_mac(self, data: bytes) -> bytes:
    primary = self._primitive_set.primary()
    if primary.output_prefix_type == tink_pb2.LEGACY:
      return primary.identifier + primary.primitive.compute_mac(
          data + core.crypto_format.LEGACY_START_BYTE)
    else:
      return primary.identifier + primary.primitive.compute_mac(data)

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    if len(mac_value) <= core.crypto_format.NON_RAW_PREFIX_SIZE:
      # This also rejects raw MAC with size of 4 bytes or fewer. Those MACs are
      # clearly insecure, thus should be discouraged.
      raise core.TinkError('tag too short')
    prefix = mac_value[:core.crypto_format.NON_RAW_PREFIX_SIZE]
    mac_no_prefix = mac_value[core.crypto_format.NON_RAW_PREFIX_SIZE:]
    for entry in self._primitive_set.primitive_from_identifier(prefix):
      try:
        if entry.output_prefix_type == tink_pb2.LEGACY:
          entry.primitive.verify_mac(mac_no_prefix, data + b'\x00')
        else:
          entry.primitive.verify_mac(mac_no_prefix, data)
        # If there is no exception, the MAC is valid and we can return.
        return
      except core.TinkError as e:
        logging.info('tag prefix matches a key, but cannot verify: %s', e)

    # No 'non-raw' key matched, so let's try the raw keys (if any exist).
    for entry in self._primitive_set.raw_primitives():
      try:
        entry.primitive.verify_mac(mac_value, data)
        # If there is no exception, the MAC is valid and we can return.
        return
      except core.TinkError as e:
        pass
    raise core.TinkError('invalid MAC')


class MacWrapper(core.PrimitiveWrapper[_mac.Mac, _mac.Mac]):
  """MacWrapper is the implementation of PrimitiveWrapper for the Mac primitive.

  The returned primitive works with a keyset (rather than a single key). To
  compute a MAC tag, it uses the primary key in the keyset, and prepends to the
  tag a certain prefix associated with the primary key. To verify a tag, the
  primitive uses the prefix of the tag to efficiently select the right key in
  the set. If the keys associated with the prefix do not validate the tag, the
  primitive tries all keys with tink_pb2.OutputPrefixType = tink_pb2.RAW.
  """

  def wrap(self, pset: core.PrimitiveSet) -> _mac.Mac:
    return _WrappedMac(pset)

  def primitive_class(self) -> Type[_mac.Mac]:
    return _mac.Mac

  def input_primitive_class(self) -> Type[_mac.Mac]:
    return _mac.Mac

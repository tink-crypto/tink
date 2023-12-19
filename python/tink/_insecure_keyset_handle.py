# Copyright 2023 Google LLC
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
"""Internal-only module that gives access to the proto keyset."""

from tink.proto import tink_pb2
from tink import _keyset_handle
from tink import _secret_key_access
from tink import core


def from_proto_keyset(
    keyset: tink_pb2.Keyset, token: core.KeyAccess
) -> _keyset_handle.KeysetHandle:
  if not isinstance(token, _secret_key_access.SecretKeyAccess):
    raise core.TinkError('no secret access.')
  return _keyset_handle.KeysetHandle._create(keyset)  # pylint: disable=protected-access


def to_proto_keyset(
    keyset_handle: _keyset_handle.KeysetHandle, token: core.KeyAccess
) -> tink_pb2.Keyset:
  if not isinstance(token, _secret_key_access.SecretKeyAccess):
    raise core.TinkError('no secret access.')
  return keyset_handle._keyset  # pylint: disable=protected-access

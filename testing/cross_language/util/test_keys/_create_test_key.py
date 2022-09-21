# Copyright 2022 Google LLC
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

"""Provides methods to create keys and keysets in cross language tests.
"""

import io
from typing import Callable

import tink
from tink import cleartext_keyset_handle

from tink.proto import tink_pb2
from util import key_util
from util.test_keys import _test_keys_container
from util.test_keys import _test_keys_db


def _use_stored_key(template: tink_pb2.KeyTemplate) -> bool:
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key'):
    return True
  return False


def new_or_stored_key(
    template: tink_pb2.KeyTemplate,
    container: _test_keys_container.TestKeysContainer = _test_keys_db.db,
    use_stored_key: Callable[[tink_pb2.KeyTemplate], bool] = _use_stored_key
) -> tink_pb2.Keyset.Key:
  """Returns either a new key or one which is stored in the passed in db.

  The arguments 'container' and 'use_stored_key' are for testing and typically
  do not need to be used.

  Args:
    template: the template for which to get a key
    container: the container with test keys, per default the container defined
      globally in _test_keys_db
    use_stored_key: a function which returns for a given template whether we
      should use a precomputed key, defaults to an internal function
  """

  if not use_stored_key(template):
    handle = tink.new_keyset_handle(template)
    buf = io.BytesIO()
    writer = tink.BinaryKeysetWriter(buf)
    cleartext_keyset_handle.write(writer, handle)
    keyset = tink_pb2.Keyset.FromString(buf.getvalue())
    return keyset.key[0]

  try:
    return container.get_key(template)
  except KeyError:
    raise ValueError('Unable to retrieve stored key for template:\n' +
                     key_util.text_format(template)) from None


def new_or_stored_keyset(
    template: tink_pb2.KeyTemplate,
    container: _test_keys_container.TestKeysContainer = _test_keys_db.db,
    use_stored_key: Callable[[tink_pb2.KeyTemplate], bool] = _use_stored_key
) -> tink_pb2.Keyset:
  """Returns a new keyset with a single new or stored key.

  The arguments 'container' and 'use_stored_key' are for testing and typically
  do not need to be used.

  Args:
    template: the template for which to get a key
    container: the container with test keys, per default the container defined
      globally in _test_keys_db
    use_stored_key: a function which returns for a given template whether we
      should use a precomputed key, defaults to an internal function
  """
  key = new_or_stored_key(template, container, use_stored_key)
  keyset = tink_pb2.Keyset(key=[key], primary_key_id=key.key_id)
  return keyset

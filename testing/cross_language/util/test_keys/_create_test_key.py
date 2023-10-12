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

from typing import Any, Callable

import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import secret_key_access
from tink import signature
from tink import streaming_aead

from tink.proto import tink_pb2
import tink_config
from util import key_util
from util.test_keys import _test_keys_container
from util.test_keys import _test_keys_db


_CREATE_NEW_KEY_MESSAGE_TEMPLATE = """
Unable to retrieve stored key for template:
{text_format}
To create a new key with this template, run:
blaze test --trim_test_configuration \\
  //third_party/tink/testing/cross_language/util:testing_servers_test \\
  --test_arg=--force_failure_for_adding_key_to_db \\
  --test_arg=--hex_template={hex_template} \\
  --test_output=errors
""".strip()


def _use_stored_key(template: tink_pb2.KeyTemplate) -> bool:
  """Returns true for templates for which we should use _test_keys_db.py."""
  # We cannot yet create ChaCha20Poly1305Keys in Python.
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key'):
    return True
  # Creating RSA Keys is very slow.
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey'):
    return True
  # Creating RSA Keys is very slow.
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey'):
    return True
  # Creating RSA Keys is very slow.
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey'):
    return True
  # Creating RSA Keys is very slow.
  if (template.type_url ==
      'type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey'):
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
    serialized_keyset = tink.proto_keyset_format.serialize(
        handle, secret_key_access.TOKEN
    )
    keyset = tink_pb2.Keyset.FromString(serialized_keyset)
    return keyset.key[0]

  try:
    return container.get_key(template)
  except KeyError:
    raise ValueError(
        _CREATE_NEW_KEY_MESSAGE_TEMPLATE.format(
            text_format=key_util.text_format(template),
            hex_template=template.SerializeToString().hex())) from None


def new_or_stored_keyset(
    template: tink_pb2.KeyTemplate,
    container: _test_keys_container.TestKeysContainer = _test_keys_db.db,
    use_stored_key: Callable[[tink_pb2.KeyTemplate], bool] = _use_stored_key
) -> bytes:
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
  return keyset.SerializeToString()


def _some_template_for_primitive(primitive: Any) -> tink_pb2.KeyTemplate:
  """Returns an arbitrary template for the given primitive."""
  if primitive == aead.Aead:
    return aead.aead_key_templates.AES128_GCM
  if primitive == daead.DeterministicAead:
    return daead.deterministic_aead_key_templates.AES256_SIV
  if primitive == streaming_aead.StreamingAead:
    return streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_1MB
  if primitive == hybrid.HybridDecrypt:
    return hybrid.hybrid_key_templates.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW
  if primitive == mac.Mac:
    return mac.mac_key_templates.HMAC_SHA256_256BITTAG
  if primitive == signature.PublicKeySign:
    return signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4
  if primitive == prf.PrfSet:
    return prf.prf_key_templates.HKDF_SHA256
  if primitive == jwt.JwtMac:
    return jwt.jwt_hs256_template()
  if primitive == jwt.JwtPublicKeySign:
    return jwt.jwt_ps512_4096_f4_template()
  raise ValueError('Unknown primitive in _some_template_for_primitive')


def _get_public_keyset(private_keyset: bytes) -> bytes:
  private_keyset_handle = tink.proto_keyset_format.parse(
      private_keyset, secret_key_access.TOKEN
  )
  return tink.proto_keyset_format.serialize_without_secret(
      private_keyset_handle.public_keyset_handle()
  )


def some_keyset_for_primitive(primitive: Any) -> bytes:
  """Returns an arbitrary keyset for the given primitive."""
  if not tink_config.is_asymmetric_public_key_primitive(primitive):
    return new_or_stored_keyset(_some_template_for_primitive(primitive))

  private_key_primitive = tink_config.get_private_key_primitive(primitive)
  private_keyset = new_or_stored_keyset(
      _some_template_for_primitive(private_key_primitive))

  return _get_public_keyset(private_keyset)

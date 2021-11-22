# Copyright 2021 Google LLC
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
"""Jwt package."""

import datetime
from typing import Dict, List, Mapping, Optional, Union, cast

from tink.jwt import _jwk_set_converter
from tink.jwt import _jwt_error
from tink.jwt import _jwt_hmac_key_manager
from tink.jwt import _jwt_key_templates
from tink.jwt import _jwt_mac
from tink.jwt import _jwt_mac_wrapper
from tink.jwt import _jwt_public_key_sign
from tink.jwt import _jwt_public_key_verify
from tink.jwt import _jwt_signature_key_manager
from tink.jwt import _jwt_signature_wrappers
from tink.jwt import _jwt_validator
from tink.jwt import _raw_jwt
from tink.jwt import _verified_jwt

JwtInvalidError = _jwt_error.JwtInvalidError
RawJwt = _raw_jwt.RawJwt
VerifiedJwt = _verified_jwt.VerifiedJwt
JwtValidator = _jwt_validator.JwtValidator
Claim = _raw_jwt.Claim
JwtMac = _jwt_mac.JwtMac
JwtPublicKeySign = _jwt_public_key_sign.JwtPublicKeySign
JwtPublicKeyVerify = _jwt_public_key_verify.JwtPublicKeyVerify

new_raw_jwt = _raw_jwt.new_raw_jwt
new_validator = _jwt_validator.new_validator

jwk_set_from_public_keyset_handle = _jwk_set_converter.from_public_keyset_handle
jwk_set_to_public_keyset_handle = _jwk_set_converter.to_public_keyset_handle

jwt_hs256_template = _jwt_key_templates.jwt_hs256_template
raw_jwt_hs256_template = _jwt_key_templates.raw_jwt_hs256_template
jwt_hs384_template = _jwt_key_templates.jwt_hs384_template
raw_jwt_hs384_template = _jwt_key_templates.raw_jwt_hs384_template
jwt_hs512_template = _jwt_key_templates.jwt_hs512_template
raw_jwt_hs512_template = _jwt_key_templates.raw_jwt_hs512_template
jwt_es256_template = _jwt_key_templates.jwt_es256_template
raw_jwt_es256_template = _jwt_key_templates.raw_jwt_es256_template
jwt_es384_template = _jwt_key_templates.jwt_es384_template
raw_jwt_es384_template = _jwt_key_templates.raw_jwt_es384_template
jwt_es512_template = _jwt_key_templates.jwt_es512_template
raw_jwt_es512_template = _jwt_key_templates.raw_jwt_es512_template
jwt_rs256_2048_f4_template = _jwt_key_templates.jwt_rs256_2048_f4_template
raw_jwt_rs256_2048_f4_template = _jwt_key_templates.raw_jwt_rs256_2048_f4_template
jwt_rs256_3072_f4_template = _jwt_key_templates.jwt_rs256_3072_f4_template
raw_jwt_rs256_3072_f4_template = _jwt_key_templates.raw_jwt_rs256_3072_f4_template
jwt_rs384_3072_f4_template = _jwt_key_templates.jwt_rs384_3072_f4_template
raw_jwt_rs384_3072_f4_template = _jwt_key_templates.raw_jwt_rs384_3072_f4_template
jwt_rs512_4096_f4_template = _jwt_key_templates.jwt_rs512_4096_f4_template
raw_jwt_rs512_4096_f4_template = _jwt_key_templates.raw_jwt_rs512_4096_f4_template
jwt_ps256_2048_f4_template = _jwt_key_templates.jwt_ps256_2048_f4_template
raw_jwt_ps256_2048_f4_template = _jwt_key_templates.raw_jwt_ps256_2048_f4_template
jwt_ps256_3072_f4_template = _jwt_key_templates.jwt_ps256_3072_f4_template
raw_jwt_ps256_3072_f4_template = _jwt_key_templates.raw_jwt_ps256_3072_f4_template
jwt_ps384_3072_f4_template = _jwt_key_templates.jwt_ps384_3072_f4_template
raw_jwt_ps384_3072_f4_template = _jwt_key_templates.raw_jwt_ps384_3072_f4_template
jwt_ps512_4096_f4_template = _jwt_key_templates.jwt_ps512_4096_f4_template
raw_jwt_ps512_4096_f4_template = _jwt_key_templates.raw_jwt_ps512_4096_f4_template


def register_jwt_mac() -> None:
  _jwt_hmac_key_manager.register()
  _jwt_mac_wrapper.register()


def register_jwt_signature() -> None:
  _jwt_signature_key_manager.register()
  _jwt_signature_wrappers.register()


# Deprecated. Use jwk_set_from_public_keyset_handle instead.
jwk_set_from_keyset_handle = _jwk_set_converter.from_keyset_handle
# Deprecated. Use jwk_set_to_public_keyset_handle instead.
jwk_set_to_keyset_handle = _jwk_set_converter.to_keyset_handle

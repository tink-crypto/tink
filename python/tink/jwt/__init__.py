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
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import datetime
from typing import Dict, List, Mapping, Optional, Text, Union, cast

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


def new_raw_jwt(*,
                type_header: Optional[Text] = None,
                issuer: Optional[Text] = None,
                subject: Optional[Text] = None,
                audiences: Optional[List[Text]] = None,
                jwt_id: Optional[Text] = None,
                expiration: Optional[datetime.datetime] = None,
                without_expiration: bool = False,
                not_before: Optional[datetime.datetime] = None,
                issued_at: Optional[datetime.datetime] = None,
                custom_claims: Optional[Mapping[Text, Claim]] = None) -> RawJwt:
  """Creates a new RawJwt."""
  return _raw_jwt.RawJwt.create(
      type_header=type_header,
      issuer=issuer,
      subject=subject,
      audiences=audiences,
      jwt_id=jwt_id,
      expiration=expiration,
      without_expiration=without_expiration,
      not_before=not_before,
      issued_at=issued_at,
      custom_claims=custom_claims)


def new_validator(
    *,
    expected_type_header: Optional[Text] = None,
    expected_issuer: Optional[Text] = None,
    expected_subject: Optional[Text] = None,
    expected_audience: Optional[Text] = None,
    ignore_type_header: bool = False,
    ignore_issuer: bool = False,
    ignore_subject: bool = False,
    ignore_audiences: bool = False,
    allow_missing_expiration: bool = False,
    clock_skew: Optional[datetime.timedelta] = None,
    fixed_now: Optional[datetime.datetime] = None) -> JwtValidator:
  """Creates a new JwtValidator."""
  return JwtValidator(
      expected_type_header=expected_type_header,
      expected_issuer=expected_issuer,
      expected_subject=expected_subject,
      expected_audience=expected_audience,
      ignore_type_header=ignore_type_header,
      ignore_issuer=ignore_issuer,
      ignore_subject=ignore_subject,
      ignore_audiences=ignore_audiences,
      allow_missing_expiration=allow_missing_expiration,
      clock_skew=clock_skew,
      fixed_now=fixed_now)


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

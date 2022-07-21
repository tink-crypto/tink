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
"""The verified JSON Web Token (JWT)."""

import datetime

from typing import List, Set

from tink import core
from tink.jwt import _raw_jwt


class VerifiedJwt:
  """A decoded and verified JSON Web Token (JWT).

  A new instance of this class is returned as the result of a sucessfully
  verification of a MACed or signed compact JWT.

  It gives read-only access all payload claims and a subset of the headers. It
  does not contain any headers that depend on the key, such as "alg" or "kid".
  These headers are checked when the signature is verified and should not be
  read by the user. This ensures that the key can be changed without any changes
  to the user code.
  """

  def __new__(cls):
    raise core.TinkError('VerifiedJwt cannot be instantiated directly.')

  @classmethod
  def _create(cls, raw_jwt: _raw_jwt.RawJwt):
    o = object.__new__(cls)
    o.__init__(raw_jwt)
    return o

  def __init__(self, raw_jwt: _raw_jwt.RawJwt) -> None:
    self._raw_jwt = raw_jwt

  def has_type_header(self) -> bool:
    return self._raw_jwt.has_type_header()

  def type_header(self) -> str:
    return self._raw_jwt.type_header()

  def has_issuer(self) -> bool:
    return self._raw_jwt.has_issuer()

  def issuer(self) -> str:
    return self._raw_jwt.issuer()

  def has_subject(self) -> bool:
    return self._raw_jwt.has_subject()

  def subject(self) -> str:
    return self._raw_jwt.subject()

  def has_audiences(self) -> bool:
    return self._raw_jwt.has_audiences()

  def audiences(self) -> List[str]:
    return self._raw_jwt.audiences()

  def has_jwt_id(self) -> bool:
    return self._raw_jwt.has_jwt_id()

  def jwt_id(self) -> str:
    return self._raw_jwt.jwt_id()

  def has_expiration(self) -> bool:
    return self._raw_jwt.has_expiration()

  def expiration(self) -> datetime.datetime:
    return self._raw_jwt.expiration()

  def has_not_before(self) -> bool:
    return self._raw_jwt.has_not_before()

  def not_before(self) -> datetime.datetime:
    return self._raw_jwt.not_before()

  def has_issued_at(self) -> bool:
    return self._raw_jwt.has_issued_at()

  def issued_at(self) -> datetime.datetime:
    return self._raw_jwt.issued_at()

  def custom_claim_names(self) -> Set[str]:
    return self._raw_jwt.custom_claim_names()

  def custom_claim(self, name: str) -> _raw_jwt.Claim:
    return self._raw_jwt.custom_claim(name)

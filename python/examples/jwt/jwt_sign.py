# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START python-jwt-sign-example]
"""A utility for creating and signing JSON Web Tokens (JWT).

It loads cleartext keys from disk - this is not recommended!
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import datetime

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import cleartext_keyset_handle
from tink import jwt


_PRIVATE_KEYSET_PATH = flags.DEFINE_string(
    'private_keyset_path', None,
    'Path to the keyset used for the JWT signature operation.')
_AUDIENCE = flags.DEFINE_string('audience', None,
                                'Audience to be used in the token')
_TOKEN_PATH = flags.DEFINE_string('token_path', None, 'Path to the token file.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    jwt.register_jwt_signature()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a KeysetHandle
  with open(_PRIVATE_KEYSET_PATH.value, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading keyset: %s', e)
      return 1

  now = datetime.datetime.now(tz=datetime.timezone.utc)

  # Get the JwtPublicKeySign primitive
  try:
    jwt_sign = keyset_handle.primitive(jwt.JwtPublicKeySign)
  except tink.TinkError as e:
    logging.exception('Error creating JwtPublicKeySign: %s', e)
    return 1

  # Create token
  raw_jwt = jwt.new_raw_jwt(
      audiences=[_AUDIENCE.value],
      expiration=now + datetime.timedelta(seconds=100))
  token = jwt_sign.sign_and_encode(raw_jwt)
  with open(_TOKEN_PATH.value, 'wt') as token_file:
    token_file.write(token)
  logging.info('Token has been written to %s', _TOKEN_PATH.value)


if __name__ == '__main__':
  flags.mark_flags_as_required(
      ['private_keyset_path', 'audience', 'token_path'])
  app.run(main)

# [END python-jwt-sign-example]

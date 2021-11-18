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

# [START python-jwt-signature-example]
"""A utility for verifying Json Web Tokens (JWT).
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
from tink import jwt


FLAGS = flags.FLAGS

flags.DEFINE_string('public_jwk_set_path', None,
                    'Path to public keyset in JWK format.')
flags.DEFINE_string('audience', None, 'Audience to be used in the token')
flags.DEFINE_string('token_path', None, 'Path to the signature file.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    jwt.register_jwt_signature()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a KeysetHandle
  with open(FLAGS.public_jwk_set_path, 'rt') as public_jwk_set_file:
    try:
      text = public_jwk_set_file.read()
      keyset_handle = jwt.jwk_set_to_keyset_handle(text)
    except tink.TinkError as e:
      logging.exception('Error reading keyset: %s', e)
      return 1

  now = datetime.datetime.now(tz=datetime.timezone.utc)
  try:
    jwt_verify = keyset_handle.primitive(jwt.JwtPublicKeyVerify)
  except tink.TinkError as e:
    logging.exception('Error creating JwtPublicKeyVerify: %s', e)
    return 1

  # Verify token
  with open(FLAGS.token_path, 'rt') as token_file:
    token = token_file.read()
  validator = jwt.new_validator(expected_audience=FLAGS.audience)
  try:
    verified_jwt = jwt_verify.verify_and_decode(token, validator)
    expires_in = verified_jwt.expiration() - now
    logging.info('Token is valid and expires in %s seconds', expires_in.seconds)
    return 0
  except tink.TinkError as e:
    logging.info('JWT verification failed: %s', e)
    return 1


if __name__ == '__main__':
  flags.mark_flags_as_required(
      ['public_jwk_set_path', 'audience', 'token_path'])
  app.run(main)

# [END python-jwt-signature-example]

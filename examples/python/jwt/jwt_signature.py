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
"""A utility for creating and verifying Json Web Tokens (JWT).

It loads cleartext keys from disk - this is not recommended!
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import datetime

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import cleartext_keyset_handle
from tink import jwt


FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['sign', 'verify'],
                  'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for the JWT signature operation.')
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

  # Read the keyset into a keyset_handle
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading keyset: %s', e)
      return 1

  now = datetime.datetime.now(tz=datetime.timezone.utc)
  if FLAGS.mode == 'sign':
    # Get the JwtPublicKeySign primitive
    try:
      jwt_sign = keyset_handle.primitive(jwt.JwtPublicKeySign)
    except tink.TinkError as e:
      logging.exception('Error creating JwtPublicKeySign: %s', e)
      return 1

    # Create token
    raw_jwt = jwt.new_raw_jwt(
        audiences=[FLAGS.audience],
        expiration=now + datetime.timedelta(seconds=100))
    token = jwt_sign.sign_and_encode(raw_jwt)
    with open(FLAGS.token_path, 'wt') as token_file:
      token_file.write(token)
    logging.info('Token has been written to %s', FLAGS.token_path)
    return 0

  # Get the JwtPublicKeyVerify primitive
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
      ['mode', 'keyset_path', 'audience', 'token_path'])
  app.run(main)

# [END python-jwt-signature-example]

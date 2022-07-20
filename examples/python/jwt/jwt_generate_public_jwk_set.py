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
"""A utility for generating the public JWK set from the public keyset.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import jwt


_PUBLIC_KEYSET_PATH = flags.DEFINE_string(
    'public_keyset_path', None,
    'Path to the public keyset in Tink JSON format.')
_PUBLIC_JWK_SET_PATH = flags.DEFINE_string(
    'public_jwk_set_path', None, 'Path to public keyset in JWK format.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    jwt.register_jwt_signature()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a KeysetHandle
  with open(_PUBLIC_KEYSET_PATH.value, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      public_keyset_handle = tink.read_no_secret_keyset_handle(
          tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading keyset: %s', e)
      return 1

  # Export Public Keyset as JWK set
  public_jwk_set = jwt.jwk_set_from_public_keyset_handle(public_keyset_handle)
  with open(_PUBLIC_JWK_SET_PATH.value, 'wt') as public_jwk_set_file:
    public_jwk_set_file.write(public_jwk_set)
  logging.info('The public JWK set has been written to %s',
               _PUBLIC_JWK_SET_PATH.value)


if __name__ == '__main__':
  flags.mark_flags_as_required(['public_keyset_path', 'public_jwk_set_path'])
  app.run(main)

# [END python-jwt-sign-example]

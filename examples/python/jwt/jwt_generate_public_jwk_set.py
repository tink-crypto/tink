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
"""A utility for generating the public JWK set from the private keyset.

It loads cleartext keys from disk - this is not recommended!
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import cleartext_keyset_handle
from tink import jwt


FLAGS = flags.FLAGS

flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for the JWT signature operation.')
flags.DEFINE_string('public_jwk_set_path', None,
                    'Path to public keyset in JWK format.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    jwt.register_jwt_signature()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a KeysetHandle
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading keyset: %s', e)
      return 1

  # Export Public Keyset as JWK set
  public_jwk_set = jwt.jwk_set_from_keyset_handle(
      keyset_handle.public_keyset_handle())
  with open(FLAGS.public_jwk_set_path, 'wt') as public_jwk_set_file:
    public_jwk_set_file.write(public_jwk_set)
  logging.info('The public JWK set has been written to %s',
               FLAGS.public_jwk_set_path)


if __name__ == '__main__':
  flags.mark_flags_as_required(
      ['keyset_path', 'public_jwk_set_path'])
  app.run(main)

# [END python-jwt-sign-example]

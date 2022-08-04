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

# [START digital-signature-example]

"""A utility for signing and verifying files using digital signatures.

It loads cleartext keys from disk - this is not recommended!
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import binascii

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import cleartext_keyset_handle
from tink import signature


FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['sign', 'verify'],
                  'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for the signature operation.')
flags.DEFINE_string('data_path', None,
                    'Path to the file with the input data.')
flags.DEFINE_string('signature_path', None,
                    'Path to the signature file.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    signature.register()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a keyset_handle
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading key: %s', e)
      return 1

  with open(FLAGS.data_path, 'rb') as data_file:
    data = data_file.read()

  if FLAGS.mode == 'sign':
    # Get the primitive
    try:
      cipher = keyset_handle.primitive(signature.PublicKeySign)
    except tink.TinkError as e:
      logging.exception('Error creating primitive: %s', e)
      return 1

    # Sign data
    sig = cipher.sign(data)
    with open(FLAGS.signature_path, 'wb') as signature_file:
      signature_file.write(binascii.hexlify(sig))
    return 0

  # Get the primitive
  try:
    cipher = keyset_handle.primitive(signature.PublicKeyVerify)
  except tink.TinkError as e:
    logging.exception('Error creating primitive: %s', e)
    return 1

  # Verify data
  with open(FLAGS.signature_path, 'rb') as signature_file:
    try:
      expected_signature = binascii.unhexlify(signature_file.read().strip())
    except binascii.Error as e:
      logging.exception('Error reading expected code: %s', e)
      return 1
  try:
    cipher.verify(expected_signature, data)
    logging.info('Signature verification succeeded.')
    return 0
  except binascii.Error as e:
    logging.exception('Error reading expected signature: %s', e)
  except tink.TinkError as e:
    logging.info('Signature verification failed.')
    return 1


if __name__ == '__main__':
  flags.mark_flags_as_required([
      'mode', 'keyset_path', 'data_path', 'signature_path'])
  app.run(main)

# [END digital-signature-example]

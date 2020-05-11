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
"""A command-line utility for using digital signature for a file.

It loads cleartext keys from disk - this is not recommended!

It requires 3 or 4 arguments:
  mode: either 'sign' or 'verify'
  keyset-file: name of the file with the keyset to be used for the digital
    signature
  data-file:  name of the file with the input data to be signed / verified
  [optional] expected-signature-file:  name of the file containing a hexadecimal
    signature with which to compare to
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
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


def main(argv):
  if len(argv) not in (4, 5):
    raise app.UsageError(
        'Expected 3 or 4 arguments, got %d.\n Usage: %s sign/verify keyset-file'
        ' data-file [expected-signature-file]' %
        (len(argv) - 1, argv[0]))

  mode = argv[1]
  keyset_filename = argv[2]
  data_filename = argv[3]

  if mode not in ['sign', 'verify']:
    logging.error('Incorrect mode. Please select "sign" or "verify".')
    return 1

  # Initialise Tink.
  try:
    signature.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a keyset_handle.
  with open(keyset_filename, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.error('Error reading key: %s', e)
      return 1

  # Get the primitive.
  try:
    if mode == 'sign':
      cipher = keyset_handle.primitive(signature.PublicKeySign)
    else:
      cipher = keyset_handle.primitive(signature.PublicKeyVerify)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(data_filename, 'rb') as data_file:
    data = data_file.read()

  # Compute the signature.
  if mode == 'sign':
    if len(argv) != 4:
      logging.error('Invalid number of parameters for signing.'
                    'Expected 3 arguments, got %d.\n Usage: %s sign '
                    'keyset-file data-file')
      return 1

    code = cipher.sign(data)
    logging.info('Signature output is %s',
                 binascii.hexlify(code).decode('utf-8'))
    return 0

  if mode == 'verify':
    if len(argv) != 5:
      logging.error('Invalid number of parameters for verification.'
                    'Expected 4 arguments, got %d.\n Usage: %s verify '
                    'keyset-file data-file [expected-signature-file]')
      return 1

    expected_code_filename = argv[4]

    with open(expected_code_filename, 'rb') as expected_code_file:
      expected_code_hex = expected_code_file.read().strip()

    logging.info(
        'Using keyset from file %s to verify file %s against expected signature on %s',
        keyset_filename, data_filename, expected_code_hex.decode('utf-8'))

    try:
      expected_signature = binascii.unhexlify(expected_code_hex)
    except binascii.Error as e:
      logging.error('Error reading expected signature: %s', e)
      return 1

    try:
      cipher.verify(expected_signature, data)
      logging.info('Signature outputs matched. Success!')
      return 0
    except tink.TinkError as e:
      logging.info('Signature outputs did not match!')
      return 1


if __name__ == '__main__':
  app.run(main)

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

"""A command-line utility for using digital signature for a file.

It loads cleartext keys from disk - this is not recommended!

It requires the following arguments:
  mode: either 'sign' or 'verify'
  keyset-file: name of the file with the keyset to be used for the digital
    signature
  data-file:  name of the file with the input data to be signed / verified
  signature-file:  name of the file containing a hexadecimal
  signature of the input file
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
  if len(argv) != 5:
    raise app.UsageError(
        'Expected 4 arguments, got %d.\n'
        'Usage: %s sign/verify keyset-file data-file signature-file' %
        (len(argv) - 1, argv[0]))

  mode = argv[1]
  keyset_filename = argv[2]
  data_filename = argv[3]
  signature_filename = argv[4]

  if mode not in ['sign', 'verify']:
    logging.error('Incorrect mode. Please select "sign" or "verify".')
    return 1

  # Initialise Tink
  try:
    signature.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a keyset_handle
  with open(keyset_filename, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.error('Error reading key: %s', e)
      return 1

  with open(data_filename, 'rb') as data_file:
    data = data_file.read()

  if mode == 'sign':
    # Get the primitive
    try:
      cipher = keyset_handle.primitive(signature.PublicKeySign)
    except tink.TinkError as e:
      logging.exception('Error creating primitive: %s', e)
      return 1

    # Sign data
    sig = cipher.sign(data)
    with open(signature_filename, 'wb') as signature_file:
      signature_file.write(binascii.hexlify(sig))
    return 0

  # Get the primitive
  try:
    cipher = keyset_handle.primitive(signature.PublicKeyVerify)
  except tink.TinkError as e:
    logging.exception('Error creating primitive: %s', e)
    return 1

  # Verify data
  with open(signature_filename, 'rb') as signature_file:
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
  app.run(main)

# [END digital-signature-example]

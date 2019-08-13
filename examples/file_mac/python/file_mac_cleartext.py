# Copyright 2019 Google Inc. All Rights Reserved.
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
"""A command-line utility for checking file integrity with a MAC.

It loads cleartext keys from disk - this is not recommended!

It requires 2 or 3 arguments:
  keyset-file: name of the file with the keyset to be used for the MAC
  data-file:  name of the file with the input data to be checked
  [optional] expected-code-file:  name of the file containing a hexadecimal MAC
  with which to compare the MAC of the input data
If expected-code-file is supplied, the program will print whether the MACs
matched or not. If not, it will just print the hexadecimal MAC of the data file.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

import binascii

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink

FLAGS = flags.FLAGS


def main(argv):
  if len(argv) not in (3, 4):
    raise app.UsageError(
        'Expected 2 or 3 arguments, got %d.\n'
        'Usage: %s keyset-file data-file [expected-code-file]' %
        (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  data_filename = argv[2]
  expected_code_filename = argv[3] if len(argv) == 4 else None

  if expected_code_filename is not None:
    with open(expected_code_filename, 'rb') as expected_code_file:
      expected_code_hex = expected_code_file.read().strip()

    logging.info(
        'Using keyset from file %s to verify file %s against expected code %s',
        keyset_filename, data_filename, expected_code_hex.decode('utf-8'))
  else:
    expected_code_hex = None
    logging.info('Using keyset from file %s to verify file %s', keyset_filename,
                 data_filename)

  # Initialise Tink.
  try:
    tink.tink_config.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset.
  with open(keyset_filename, 'rb') as keyset_file:
    try:
      text = keyset_file.read()
      keyset = tink.KeysetHandle(tink.JsonKeysetReader(text).read())
    except tink.TinkError as e:
      logging.error('Error reading key: %s', e)
      return 1

  # Get the primitive.
  try:
    cipher = keyset.primitive(tink.Mac)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Compute the MAC.
  with open(data_filename, 'rb') as data_file:
    data = data_file.read()

  if expected_code_hex is None:
    code = cipher.compute_mac(data)
    logging.info('MAC output is %s', binascii.hexlify(code).decode('utf-8'))
    return 0

  try:
    expected_code = binascii.unhexlify(expected_code_hex)
  except binascii.Error as e:
    logging.error('Error reading expected code: %s', e)
    return 1

  try:
    cipher.verify_mac(expected_code, data)
    logging.info('MAC outputs matched. Success!')
    return 0
  except tink.TinkError as e:
    logging.info('MAC outputs did not match!')
    code = binascii.hexlify(cipher.compute_mac(data)).decode('utf-8')
    logging.info('Actual MAC output is %s', code)
    return 1


if __name__ == '__main__':
  app.run(main)

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
# [START mac-example]
"""A command-line utility for checking file integrity with a Message Authentication Code (MAC).

It loads cleartext keys from disk - this is not recommended!

It requires the following arguments:
  mode: either 'compute' or 'verify'
  keyset-file: name of the file with the keyset to be used for the MAC
  data-file:  name of the file with the input data to be checked
  mac-file:  name of the file containing a hexadecimal MAC of the data
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
from tink import mac

FLAGS = flags.FLAGS


def main(argv):
  if len(argv) != 5:
    raise app.UsageError(
        'Expected 4 arguments, got %d.\n'
        'Usage: %s compute/verify keyset-file data-file mac-file' %
        (len(argv) - 1, argv[0]))

  mode = argv[1]
  if mode not in ('compute', 'verify'):
    raise app.UsageError('Incorrect mode. Please select compute or verify.')

  keyset_filename = argv[2]
  data_filename = argv[3]
  mac_filename = argv[4]

  # Initialise Tink.
  try:
    mac.register()
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
    cipher = keyset_handle.primitive(mac.Mac)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(data_filename, 'rb') as data_file:
    data = data_file.read()

  if mode == 'compute':
    # Compute the MAC.
    code = cipher.compute_mac(data)
    with open(mac_filename, 'wb') as mac_file:
      mac_file.write(binascii.hexlify(code))
    return 0

  with open(mac_filename, 'rb') as mac_file:
    try:
      expected_mac = binascii.unhexlify(mac_file.read().strip())
    except binascii.Error as e:
      logging.exception('Error reading expected code: %s', e)
      return 1

  try:
    cipher.verify_mac(expected_mac, data)
    logging.info('MAC verification succeeded.')
    return 0
  except tink.TinkError as e:
    logging.info('MAC verification failed.')
    return 1


if __name__ == '__main__':
  app.run(main)
# [END mac-example]

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
from tink import mac

FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['compute', 'verify'],
                  'The operation to perform.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for the MAC operation.')
flags.DEFINE_string('data_path', None,
                    'Path to the file with the input data to be checked.')
flags.DEFINE_string('mac_path', None,
                    'Path to the file containing a hexadecimal MAC of the'
                    ' data.')


def main(argv):
  del argv  # Unused.

  # Initialise Tink.
  try:
    mac.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a keyset_handle.
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
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

  with open(FLAGS.data_path, 'rb') as data_file:
    data = data_file.read()

  if FLAGS.mode == 'compute':
    # Compute the MAC.
    code = cipher.compute_mac(data)
    with open(FLAGS.mac_path, 'wb') as mac_file:
      mac_file.write(binascii.hexlify(code))
    return 0

  with open(FLAGS.mac_path, 'rb') as mac_file:
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
  flags.mark_flags_as_required([
      'mode', 'keyset_path', 'data_path', 'mac_path'])
  app.run(main)
# [END mac-example]

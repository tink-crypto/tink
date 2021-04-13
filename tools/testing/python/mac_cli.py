# Copyright 2020 Google LLC
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
"""A command-line utility for testing Mac-primitives.

It requires 4 arguments for MAC computation and 5 for MAC verification:
  keyset-file:  name of the file with the keyset to be used for encryption
  operation: the Mac-operation, i.e. "compute" or "verify"
  data-file:  name of the file with data for MAC computation/verification
  mac-file:  name of the file for MAC value (when computing MAC), or with MAC
             MAC value (when verifiying the MAC)
  result-file:  name of the file for MAC verification result (valid/invalid)
                (only for MAC verification operation)
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
from tink import mac

FLAGS = flags.FLAGS


def read_keyset(keyset_filename):
  """Load a keyset from a file.

  Args:
    keyset_filename: A path to a keyset file

  Returns:
    A KeysetHandle of the file's keyset
  Raises:
    TinkError: if the file is not valid
    IOError: if the file does not exist
  """
  with open(keyset_filename, 'rb') as keyset_file:
    text = keyset_file.read()
    keyset = cleartext_keyset_handle.read(tink.BinaryKeysetReader(text))
  return keyset


def main(argv):
  if len(argv) not in (5, 6):
    raise app.UsageError(
        'Expected 5 or 6 arguments, got %d.\n'
        'Usage: %s keyset-file operation input-file associated-data-file' %
        (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  operation = argv[2]
  data_filename = argv[3]
  mac_filename = argv[4]
  if len(argv) == 6:
    result_filename = argv[5]

  logging.info(
      'Using keyset from file %s to %s MAC on file %s.\n The resulting output'
      'will be written to file %s',
      keyset_filename, operation, data_filename, mac_filename)

  # Initialise Tink
  try:
    mac.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into keyset_handle
  try:
    keyset_handle = read_keyset(keyset_filename)
  except tink.TinkError as e:
    logging.error('Error reading key: %s', e)
    return 1

  # Get the primitive
  try:
    mac_primitive = keyset_handle.primitive(mac.Mac)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Read the input files
  with open(data_filename, 'rb') as input_file:
    input_data = input_file.read()

  # Compute the output
  if operation.lower() == 'compute':
    try:
      tag = mac_primitive.compute_mac(input_data)
    except tink.TinkError as e:
      logging.error('Error computing MAC on the input: %s', e)

    # Write MAC to file
    with open(mac_filename, 'wb') as mac_file:
      mac_file.write(tag)

  elif operation.lower() == 'verify':
    # Read MAC from file
    with open(mac_filename, 'rb') as mac_file:
      tag = mac_file.read()
    # Check for valid MAC
    try:
      mac_primitive.verify_mac(tag, input_data)
      result = b'valid'
    except tink.TinkError as e:
      logging.error('Error verifying MAC of the input: %s', e)
      result = b'invalid'
    with open(result_filename, 'wb') as result_file:
      result_file.write(result)
  else:
    logging.error(
        'Did not recognise operation %s.\n'
        'Expected either "compute" or "verify"', operation)
    return 1

  logging.info('All done.')


if __name__ == '__main__':
  app.run(main)

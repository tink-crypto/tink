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
"""A command-line utility for testing PublicKeySign primitives.

It requires 3 arguments:
   keyset-file:  name of the file with the keyset to be used for signing
   message-file:  name of the file that contains message to be signed
   output-file:  name of the output file for the resulting plaintext
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
from tink import signature

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
  if len(argv) != 4:
    raise app.UsageError(
        'Expected 3 arguments, got %d.\n'
        'Usage: %s keyset-file message-file output-file' %
        (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  message_filename = argv[2]
  output_filename = argv[3]

  logging.info(
      'Using keyset from file %s to sign %s file.\n'
      'The signature will be written to file %s\n',
      keyset_filename, message_filename, output_filename)

  # Initialise Tink
  try:
    signature.register()
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
    sign_primitive = keyset_handle.primitive(signature.PublicKeySign)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Read the message
  with open(message_filename, 'rb') as message_file:
    message_data = message_file.read()

  try:
    signature_data = sign_primitive.sign(message_data)
  except tink.TinkError as e:
    logging.error('Error signing the message: %s', e)
    return 1

  with open(output_filename, 'wb') as output_file:
    output_file.write(signature_data)

  logging.info('All done.')


if __name__ == '__main__':
  app.run(main)

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
"""A command-line utility for testing HybridEncrypt-primitives.

It requires 4 arguments:
   keyset-file:  name of the file with the keyset to be used for encrypting
   plaintext-file:  name of the file that contains plaintext to be encrypted
   contextinfo-file: name of the file that contains contextinfo used for
                     encryption
   output-file:  name of the output file for the resulting encryptedtext
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
from tink import hybrid

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
  if len(argv) != 5:
    raise app.UsageError(
        'Expected 4 arguments, got %d.\n'
        'Usage: %s keyset-file plaintext-file contextinfo-file output-file' %
        (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  plaintext_filename = argv[2]
  contextinfo_filename = argv[3]
  output_filename = argv[4]

  logging.info(
      'Using keyset from file %s to HybridEncrypt file %s using context '
      'info %s\n.The resulting output will be written to file %s',
      keyset_filename, plaintext_filename, contextinfo_filename,
      output_filename)

  # Initialise Tink
  try:
    hybrid.register()
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
    cipher = keyset_handle.primitive(hybrid.HybridEncrypt)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Read the input files
  with open(plaintext_filename, 'rb') as plaintext_file:
    plaintext_data = plaintext_file.read()
  with open(contextinfo_filename, 'rb') as contextinfo_file:
    contextinfo_data = contextinfo_file.read()

  try:
    output_data = cipher.encrypt(plaintext_data, contextinfo_data)
  except tink.TinkError as e:
    logging.error('Error encrypting the input: %s', e)
    return 1

  with open(output_filename, 'wb') as output_file:
    output_file.write(output_data)

  logging.info('All done.')


if __name__ == '__main__':
  app.run(main)

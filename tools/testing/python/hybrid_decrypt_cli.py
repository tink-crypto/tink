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
"""A command-line utility for testing HybridDecrypt-primitives.

It requires 4 arguments:
   keyset-file:  name of the file with the keyset to be used for decrypting
   encrypted-file:  name of the file that contains ciphertext to be decrypted
   contextinfo-file: name of the file that contains contextinfo used for
                     decryption
   output-file:  name of the output file for the resulting encrypted
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
        'Usage: %s keyset-file encrypted-file contextinfo-file output-file' %
        (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  encrypted_filename = argv[2]
  contextinfo_filename = argv[3]
  output_filename = argv[4]

  logging.info(
      'Using keyset from file %s to HybridDecrypt file %s using context '
      'info %s\n.The resulting output will be written to file %s',
      keyset_filename, encrypted_filename, contextinfo_filename,
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
    cipher = keyset_handle.primitive(hybrid.HybridDecrypt)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Read the input files
  with open(encrypted_filename, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
  with open(contextinfo_filename, 'rb') as contextinfo_file:
    contextinfo_data = contextinfo_file.read()

  try:
    plaintext_data = cipher.decrypt(encrypted_data, contextinfo_data)
  except tink.TinkError as e:
    logging.error('Error decrypting the input: %s', e)
    return 1

  with open(output_filename, 'wb') as output_file:
    output_file.write(plaintext_data)

  logging.info('All done.')


if __name__ == '__main__':
  app.run(main)

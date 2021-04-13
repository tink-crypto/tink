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

# [START streaming-aead-example]
"""A command-line utility for using streaming AEAD for a file.

It loads cleartext keys from disk - this is not recommended!

It requires 4 arguments (and one optional one):
  mode: either 'encrypt' or 'decrypt'
  keyset_path: name of the file with the keyset to be used for encryption or
    decryption
  input_path: name of the file with the input data to be encrypted or decrypted
  output_path: name of the file to write the ciphertext respectively plaintext
    to
  [optional] associated_data: the associated data used for encryption/decryption
    provided as a string.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import BinaryIO

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink
from tink import cleartext_keyset_handle
from tink import streaming_aead

FLAGS = flags.FLAGS
BLOCK_SIZE = 1024 * 1024  # The CLI tool will read/write at most 1 MB at once.

flags.DEFINE_enum('mode', None, ['encrypt', 'decrypt'],
                  'Selects if the file should be encrypted or decrypted.')
flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for encryption or decryption.')
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')
flags.DEFINE_string('associated_data', None,
                    'Associated data used for the encryption or decryption.')


def read_as_blocks(file: BinaryIO):
  """Generator function to read from a file BLOCK_SIZE bytes.

  Args:
    file: The file object to read from.

  Yields:
    Returns up to BLOCK_SIZE bytes from the file.
  """
  while True:
    data = file.read(BLOCK_SIZE)
    # If file was opened in rawIO, EOF is only reached when b'' is returned.
    # pylint: disable=g-explicit-bool-comparison
    if data == b'':
      break
    # pylint: enable=g-explicit-bool-comparison
    yield data


def encrypt_file(input_file: BinaryIO, output_file: BinaryIO,
                 associated_data: bytes,
                 primitive: streaming_aead.StreamingAead):
  """Encrypts a file with the given streaming AEAD primitive.

  Args:
    input_file: File to read from.
    output_file: File to write to.
    associated_data: Associated data provided for the AEAD.
    primitive: The streaming AEAD primitive used for encryption.
  """
  with primitive.new_encrypting_stream(output_file,
                                       associated_data) as enc_stream:
    for data_block in read_as_blocks(input_file):
      enc_stream.write(data_block)


def decrypt_file(input_file: BinaryIO, output_file: BinaryIO,
                 associated_data: bytes,
                 primitive: streaming_aead.StreamingAead):
  """Decrypts a file with the given streaming AEAD primitive.

  This function will cause the program to exit with 1 if the decryption fails.

  Args:
    input_file: File to read from.
    output_file: File to write to.
    associated_data: Associated data provided for the AEAD.
    primitive: The streaming AEAD primitive used for decryption.
  """
  try:
    with primitive.new_decrypting_stream(input_file,
                                         associated_data) as dec_stream:
      for data_block in read_as_blocks(dec_stream):
        output_file.write(data_block)
  except tink.TinkError as e:
    logging.exception('Error decrypting ciphertext: %s', e)
    exit(1)


def main(argv):
  del argv

  associated_data = b'' if not FLAGS.associated_data else bytes(
      FLAGS.associated_data, 'utf-8')

  # Initialise Tink.
  try:
    streaming_aead.register()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into a keyset_handle.
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError as e:
      logging.exception('Error reading key: %s', e)
      return 1

  # Get the primitive.
  try:
    streaming_aead_primitive = keyset_handle.primitive(
        streaming_aead.StreamingAead)
  except tink.TinkError as e:
    logging.exception('Error creating streaming AEAD primitive from keyset: %s',
                      e)
    return 1

  # Encrypt or decrypt the file.
  with open(FLAGS.input_path, 'rb') as input_file:
    with open(FLAGS.output_path, 'wb') as output_file:
      if FLAGS.mode == 'encrypt':
        encrypt_file(input_file, output_file, associated_data,
                     streaming_aead_primitive)
      elif FLAGS.mode == 'decrypt':
        decrypt_file(input_file, output_file, associated_data,
                     streaming_aead_primitive)


if __name__ == '__main__':
  flags.mark_flag_as_required('mode')
  flags.mark_flag_as_required('keyset_path')
  flags.mark_flag_as_required('input_path')
  flags.mark_flag_as_required('output_path')
  app.run(main)

# [END streaming-aead-example]

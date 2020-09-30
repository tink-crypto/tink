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
"""A command-line utility for decrypting files using hybrid encryption.

It loads cleartext keys from disk - this is not recommended!

It requires 3 arguments (and one optional one):
  keyset_path: name of the file with the private keyset for decryption.
  input_path: name of the file with the input data to be decrypted.
  output_path: name of the file to write the plaintext to.
  [optional] context_info: the context info used for decryption provided as a
    string.
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

flags.DEFINE_string('keyset_path', None,
                    'Path to the keyset used for decryption.')
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')
flags.DEFINE_string('context_info', None,
                    'Context info used for the decryption.')

FLAGS = flags.FLAGS


def main(argv):
  del argv

  context_info = b'' if not FLAGS.context_info else bytes(
      FLAGS.context_info, 'utf-8')

  # Initialise Tink.
  try:
    hybrid.register()
  except tink.TinkError:
    logging.exception('Error initialising Tink.')
    return 1

  # Read the keyset into a keyset_handle.
  with open(FLAGS.keyset_path, 'rt') as keyset_file:
    text = keyset_file.read()
    try:
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
    except tink.TinkError:
      logging.exception('Error reading key.')
      return 1

  # Get the primitive.
  try:
    primitive = keyset_handle.primitive(hybrid.HybridDecrypt)
  except tink.TinkError:
    logging.exception(
        'Error creating hybrid decrypt primitive from keyset.')
    return 1

  with open(FLAGS.input_path, 'rb') as input_file:
    with open(FLAGS.output_path, 'wb') as output_file:
      data = input_file.read()
      plaintext = primitive.decrypt(data, context_info)
      output_file.write(plaintext)


if __name__ == '__main__':
  flags.mark_flag_as_required('keyset_path')
  flags.mark_flag_as_required('input_path')
  flags.mark_flag_as_required('output_path')
  app.run(main)

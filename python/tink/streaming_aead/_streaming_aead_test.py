# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.python.tink.streaming_aead.streaming_aead."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
import os
import tempfile

from absl.testing import absltest

import tink
from tink import streaming_aead


def setUpModule():
  streaming_aead.register()


def get_primitive() -> streaming_aead.StreamingAead:
  key_template = streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB
  keyset_handle = tink.new_keyset_handle(key_template)
  primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
  return primitive


class StreamingAeadTest(absltest.TestCase):
  """End-to-end test of Streaming AEAD Encrypting/Decrypting Streams."""

  def test_encrypt_decrypt(self):
    primitive = get_primitive()
    long_plaintext = b' '.join(b'%d' % i for i in range(100 * 1000))
    aad = b'associated_data'
    with tempfile.TemporaryDirectory() as tmpdirname:
      filename = os.path.join(tmpdirname, 'encrypted_file')
      dest = open(filename, 'wb')
      with primitive.new_encrypting_stream(dest, aad) as es:
        n = es.write(long_plaintext)
      self.assertTrue(dest.closed)
      self.assertLen(long_plaintext, n)

      src = open(filename, 'rb')
      with primitive.new_decrypting_stream(src, aad) as ds:
        output = ds.read()
      self.assertTrue(src.closed)
      self.assertEqual(output, long_plaintext)

  def test_encrypt_decrypt_raw(self):
    primitive = get_primitive()
    long_plaintext = b' '.join(b'%d' % i for i in range(100 * 1000))
    aad = b'associated_data'
    with tempfile.TemporaryDirectory() as tmpdirname:
      filename = os.path.join(tmpdirname, 'encrypted_file_raw')
      dest = open(filename, 'wb', buffering=0)  # returns a raw file.
      with primitive.new_encrypting_stream(dest, aad) as es:
        n = es.write(long_plaintext)
      self.assertTrue(dest.closed)
      self.assertLen(long_plaintext, n)

      src = open(filename, 'rb', buffering=0)  # returns a raw file.
      with primitive.new_decrypting_stream(src, aad) as ds:
        output = ds.read()
      self.assertTrue(src.closed)
      self.assertEqual(output, long_plaintext)

  def test_encrypt_decrypt_textiowrapper(self):
    primitive = get_primitive()
    text_lines = [
        'ᚻᛖ ᚳᚹᚫᚦ ᚦᚫᛏ ᚻᛖ ᛒᚢᛞᛖ ᚩᚾ ᚦᚫᛗ ᛚᚪᚾᛞᛖ ᚾᚩᚱᚦᚹᛖᚪᚱᛞᚢᛗ ᚹᛁᚦ ᚦᚪ ᚹᛖᛥᚫ\n',
        '⡌⠁⠧⠑ ⠼⠁⠒  ⡍⠜⠇⠑⠹⠰⠎ ⡣⠕⠌\n',
        '2H₂ + O₂ ⇌ 2H₂O\n',
        'smile 😀\n']
    aad = b'associated_data'
    with tempfile.TemporaryDirectory() as tmpdirname:
      filename = os.path.join(tmpdirname, 'encrypted_textfile')
      dest = open(filename, 'wb')
      with io.TextIOWrapper(
          primitive.new_encrypting_stream(dest, aad), encoding='utf8') as es:
        es.writelines(text_lines)
      self.assertTrue(dest.closed)

      src = open(filename, 'rb')
      with io.TextIOWrapper(
          primitive.new_decrypting_stream(src, aad), encoding='utf8') as es:
        for i, text_line in enumerate(es):
          self.assertEqual(text_line, text_lines[i])
      self.assertTrue(src.closed)

  def test_encrypt_fails_on_nonwritable_stream(self):
    primitive = get_primitive()
    with tempfile.TemporaryDirectory() as tmpdirname:
      filename = os.path.join(tmpdirname, 'file')
      with open(filename, 'wb') as f:
        f.write(b'data')
      with open(filename, 'rb') as dest:  # dest is not writable
        with self.assertRaises(ValueError):
          primitive.new_encrypting_stream(dest, b'aad')

  def test_decrypt_fails_on_nonreadable_stream(self):
    primitive = get_primitive()
    with tempfile.TemporaryDirectory() as tmpdirname:
      # src not readable
      with open(os.path.join(tmpdirname, 'file2'), 'wb') as src:
        with self.assertRaises(ValueError):
          primitive.new_decrypting_stream(src, b'aad')

if __name__ == '__main__':
  absltest.main()

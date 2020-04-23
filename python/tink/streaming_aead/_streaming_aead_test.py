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

from absl.testing import absltest

from tink import streaming_aead
from tink import tink_config

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'
B_AAD_ = b'aa' + B_X80
B_TEST_AAD_ = b'test aa' + B_X80


def setUpModule():
  tink_config.register()


class TestBytesObject(io.BytesIO):
  """A BytesIO object that does not close."""

  def close(self):
    pass


class StreamingAeadTest(absltest.TestCase):
  """End-to-end test of Streaming AEAD Encrypting/Decrypting Streams."""

  @staticmethod
  def get_primitive():
    key_manager = streaming_aead.key_manager_from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey')

    # Generate the key data.
    key_template = streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB
    key_data = key_manager.new_key_data(key_template)

    return key_manager.primitive(key_data)

  def test_get_encrypting_stream(self):
    primitive = self.get_primitive()

    # Use the primitive to get an encrypting stream.
    with TestBytesObject() as f:
      with primitive.new_encrypting_stream(f, B_AAD_) as es:
        es.write(b'some data' + B_X80)

      ciphertext = f.getvalue()
      self.assertNotEmpty(ciphertext)

  def test_get_two_encrypting_streams(self):
    """Test that multiple EncryptingStreams can be obtained from a primitive."""
    primitive = self.get_primitive()

    f1 = TestBytesObject()
    f2 = TestBytesObject()

    with primitive.new_encrypting_stream(f1, B_AAD_) as es:
      es.write(b'some data' + B_X80)

    with primitive.new_encrypting_stream(f2, b'another aad' + B_X80) as es:
      es.write(b'some other data' + B_X80)

    self.assertNotEmpty(f1.getvalue())
    self.assertNotEmpty(f2.getvalue())

  def test_encrypting_textiowrapper(self):
    """A test that checks the TextIOWrapper works as expected.

    It encrypts the same plaintext twice - once directly from bytes, and once
    through TextIOWrapper's encoding. The two ciphertexts should have the same
    length.
    """
    primitive = self.get_primitive()

    file_1 = TestBytesObject()
    file_2 = TestBytesObject()

    with primitive.new_encrypting_stream(file_1, B_AAD_) as es:
      with io.TextIOWrapper(es) as wrapper:
        wrapper.write(b'some data'.decode('utf-8'))

    with primitive.new_encrypting_stream(file_2, B_AAD_) as es:
      es.write(b'some data')

    self.assertEqual(len(file_1.getvalue()), len(file_2.getvalue()))

  def test_round_trip(self):
    primitive = self.get_primitive()

    f = TestBytesObject()

    original_plaintext = b'some data' + B_X80

    with primitive.new_encrypting_stream(f, B_TEST_AAD_) as es:
      es.write(original_plaintext)

    f.seek(0)

    with primitive.new_decrypting_stream(f, B_TEST_AAD_) as ds:
      read_plaintext = ds.read()

    self.assertEqual(read_plaintext, original_plaintext)

  def test_round_trip_textiowrapper_single_line(self):
    """Read and write a single line through a TextIOWrapper."""
    primitive = self.get_primitive()
    f = TestBytesObject()

    original_plaintext = b'One-line string.'.decode('utf-8')
    with primitive.new_encrypting_stream(f, B_TEST_AAD_) as es:
      with io.TextIOWrapper(es) as wrapper:
        wrapper.write(original_plaintext)

    f.seek(0)

    with primitive.new_decrypting_stream(f, B_TEST_AAD_) as ds:
      with io.TextIOWrapper(ds) as wrapper:
        read_plaintext = wrapper.read()

    self.assertEqual(original_plaintext, read_plaintext)

  def test_round_trip_decrypt_textiowrapper(self):
    """Write bytes to EncryptingStream, then decrypt through TextIOWrapper."""
    primitive = self.get_primitive()
    f = TestBytesObject()
    original_plaintext = '''some
    data
    on multiple lines.'''

    with primitive.new_encrypting_stream(f, B_TEST_AAD_) as es:
      es.write(original_plaintext.encode('utf-8'))

    f.seek(0)
    with primitive.new_decrypting_stream(f, B_TEST_AAD_) as ds:
      with io.TextIOWrapper(ds) as wrapper:
        data = wrapper.read()

    self.assertEqual(data, original_plaintext)

  def test_round_trip_encrypt_textiowrapper(self):
    """Encrypt with TextIOWrapper, then decrypt direct bytes."""
    primitive = self.get_primitive()
    f = TestBytesObject()
    original_plaintext = b'''some
    data
    on multiple lines.'''.decode('utf-8')

    with primitive.new_encrypting_stream(f, B_TEST_AAD_) as es:
      with io.TextIOWrapper(es) as wrapper:
        wrapper.write(original_plaintext)

    f.seek(0)
    with primitive.new_decrypting_stream(f, B_TEST_AAD_) as ds:
      data = ds.read().decode('utf-8')

    self.assertEqual(data, original_plaintext)

  def test_round_trip_encrypt_decrypt_textiowrapper(self):
    """Use TextIOWrapper for both encryption and decryption."""
    primitive = self.get_primitive()
    f = TestBytesObject()
    original_plaintext = b'''some
    data
    on multiple lines.'''.decode('utf-8')

    with primitive.new_encrypting_stream(f, B_TEST_AAD_) as es:
      with io.TextIOWrapper(es) as wrapper:
        wrapper.write(original_plaintext)

    f.seek(0)
    with primitive.new_decrypting_stream(f, B_TEST_AAD_) as ds:
      with io.TextIOWrapper(ds) as wrapper:
        data = wrapper.read()

    self.assertEqual(data, original_plaintext)

if __name__ == '__main__':
  absltest.main()

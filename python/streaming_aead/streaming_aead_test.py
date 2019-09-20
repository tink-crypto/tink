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
"""Tests for tink.python.streaming_aead.streaming_aead."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

import io

from absl.testing import absltest

from tink.python import tink_config
from tink.python.streaming_aead import streaming_aead_key_manager
from tink.python.streaming_aead import streaming_aead_key_templates


def setUpModule():
  tink_config.register()


class TestBytesObject(io.BytesIO):
  """A BytesIO object that does not close."""

  def close(self):
    pass


class StreamingAeadTest(absltest.TestCase):
  """End-to-end test of Streaming AEAD Encrypting Streams."""

  @staticmethod
  def get_primitive():
    key_manager = streaming_aead_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey')

    # Generate the key data.
    key_template = streaming_aead_key_templates.AES128_GCM_HKDF_4KB
    key_data = key_manager.new_key_data(key_template)

    return key_manager.primitive(key_data)

  def test_get_encrypting_stream(self):
    # Get the primitive.
    primitive = self.get_primitive()

    # Use the primitive to get an encrypting stream.
    with TestBytesObject() as f:
      with primitive.new_encrypting_stream(f, b'aad') as es:
        es.write(b'some data')

      ciphertext = f.getvalue()
      self.assertNotEmpty(ciphertext)

  def test_get_two_encrypting_streams(self):
    """Test that multiple EncryptingStreams can be obtained from a primitive."""
    # Get the primitive.
    primitive = self.get_primitive()

    f1 = TestBytesObject()
    f2 = TestBytesObject()

    with primitive.new_encrypting_stream(f1, b'aad') as es:
      es.write(b'some data')

    with primitive.new_encrypting_stream(f2, b'another aad') as es:
      es.write(b'some other data')

    self.assertNotEmpty(f1.getvalue())
    self.assertNotEmpty(f2.getvalue())

  def test_textiowrapper_compatibility(self):
    """A test that checks the TextIOWrapper works as expected.

    It encrypts the same plaintext twice - once directly from bytes, and once
    through TextIOWrapper's encoding. The two ciphertexts should have the same
    length.
    """
    # Get the primitive.
    primitive = self.get_primitive()

    file_1 = TestBytesObject()
    file_2 = TestBytesObject()

    with primitive.new_encrypting_stream(file_1, b'aad') as es:
      with io.TextIOWrapper(es) as wrapper:
        # Need to specify this is a unicode string for Python 2.
        wrapper.write(u'some data')

    with primitive.new_encrypting_stream(file_2, b'aad') as es:
      es.write(b'some data')

    self.assertEqual(len(file_1.getvalue()), len(file_2.getvalue()))


if __name__ == '__main__':
  absltest.main()

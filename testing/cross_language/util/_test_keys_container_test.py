# Copyright 2022 Google LLC
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
"""Tests for _test_keys_container."""

from absl.testing import absltest

from tink.proto import tink_pb2
from util import _test_keys_container


class TestKeysContainerTest(absltest.TestCase):

  def test_insert_and_retrieve(self):
    container = _test_keys_container.TestKeysContainer()
    container.add_key(
        template=r"""
          type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
          # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
          # }
          value: ""
          output_prefix_type: RAW""",
        key=r"""
          key_data {
            type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
            #   version: 0
            #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            # }
            value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            key_material_type: SYMMETRIC
          }
          status: ENABLED
          key_id: 1349954765
          output_prefix_type: RAW""")
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key',
        output_prefix_type=tink_pb2.RAW)

    key = container.get_key(template)
    self.assertEqual(key.status, tink_pb2.ENABLED)
    self.assertEqual(key.key_id, 1349954765)
    self.assertEqual(key.output_prefix_type, tink_pb2.RAW)
    self.assertEqual(key.key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    self.assertEqual(
        key.key_data.value,
        b'\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611'
    )

  def test_element_not_present_throws(self):
    container = _test_keys_container.TestKeysContainer()
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key',
        output_prefix_type=tink_pb2.RAW)
    with self.assertRaises(KeyError):
      container.get_key(template)

  def test_wrong_format_throws(self):
    valid_template = r"""
      type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
      # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
      # }
      value: ""
      output_prefix_type: RAW"""
    valid_key = r"""
      key_data {
        type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
        # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
        #   version: 0
        #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
        # }
        value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
        key_material_type: SYMMETRIC
      }
      status: ENABLED
      key_id: 1349954765
      output_prefix_type: RAW"""
    container = _test_keys_container.TestKeysContainer()
    with self.assertRaises(AssertionError):
      container.add_key('# Comment\n' + valid_template, valid_key)
    with self.assertRaises(AssertionError):
      container.add_key(valid_template, '# Comment\n' + valid_key)

    # To check that the above constants are valid, we insert them
    container.add_key(valid_template, valid_key)

  def test_multiple_keys_works(self):
    container = _test_keys_container.TestKeysContainer()
    container.add_key(
        template=r"""
          type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
          # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
          # }
          value: ""
          output_prefix_type: RAW""",
        key=r"""
          key_data {
            type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
            #   version: 0
            #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            # }
            value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            key_material_type: SYMMETRIC
          }
          status: ENABLED
          key_id: 1349954765
          output_prefix_type: RAW""")
    container.add_key(
        template=r"""
          type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
          # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
          # }
          value: ""
          output_prefix_type: TINK""",
        key=r"""
          key_data {
            type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
            #   version: 0
            #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            # }
            value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            key_material_type: SYMMETRIC
          }
          status: ENABLED
          key_id: 1349954765
          output_prefix_type: TINK""")
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key',
        output_prefix_type=tink_pb2.RAW)
    self.assertEqual(
        container.get_key(template).output_prefix_type, tink_pb2.RAW)
    template.output_prefix_type = tink_pb2.TINK
    self.assertEqual(
        container.get_key(template).output_prefix_type, tink_pb2.TINK)

  def test_insert_same_template_twice_fails(self):
    container = _test_keys_container.TestKeysContainer()
    container.add_key(
        template=r"""
          type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
          # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
          # }
          value: ""
          output_prefix_type: RAW""",
        key=r"""
          key_data {
            type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
            #   version: 0
            #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            # }
            value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
            key_material_type: SYMMETRIC
          }
          status: ENABLED
          key_id: 1349954765
          output_prefix_type: RAW""")
    with self.assertRaises(ValueError):
      container.add_key(
          template=r"""
            type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305KeyFormat] {
            # }
            value: ""
            output_prefix_type: RAW""",
          key=r"""
            key_data {
              type_url: "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
              # value: [type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key] {
              #   version: 0
              #   key_value: "\372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
              # }
              value: "\022 \372\022\371\335\313\301\314\253\r\364\376\341o\242\375\000p\317,t\326\373U\332\267\342\212\210\2160\3611"
              key_material_type: SYMMETRIC
            }
            status: ENABLED
            key_id: 1349954764
            output_prefix_type: TINK""")


if __name__ == '__main__':
  absltest.main()

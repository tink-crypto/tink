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

"""Database of precomputed Tink Keys for the cross language tests.
"""
from util.test_keys import _test_keys_container

db = _test_keys_container.TestKeysContainer()

db.add_key(
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

db.add_key(
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
        #   key_value: ".\361n\315k\373\266\030\234N\360~6d\304sZ\325*\005\355\010~\376#\352\221<\214@*s"
        # }
        value: "\022 .\361n\315k\373\266\030\234N\360~6d\304sZ\325*\005\355\010~\376#\352\221<\214@*s"
        key_material_type: SYMMETRIC
      }
      status: ENABLED
      key_id: 653548180
      output_prefix_type: TINK""")

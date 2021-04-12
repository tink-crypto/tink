// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;

/** Helper functions for testing {@link KeyTypeManager} objects. */
public class KeyTypeManagerTestUtil {

  private static <KeyFormatProtoT extends MessageLite, KeyProtoT extends MessageLite>
      KeyProtoT parseValidateCreateKey(
          KeyTypeManager.KeyFactory<KeyFormatProtoT, KeyProtoT> factory, KeyTemplate template)
          throws Exception {
    KeyFormatProtoT format = factory.parseKeyFormat(ByteString.copyFrom(template.getValue()));
    factory.validateKeyFormat(format);
    return factory.createKey(format);
  }

  /**
   * Checks that the given keyTemplate will be handed to the given KeyTypeManager (if registered),
   * that it validates, and returns a key if needed.
   */
  public static <KeyProtoT extends MessageLite> KeyProtoT testKeyTemplateCompatible(
      KeyTypeManager<KeyProtoT> manager, KeyTemplate template) throws Exception {
    assertThat(template.getTypeUrl()).isEqualTo(manager.getKeyType());
    return parseValidateCreateKey(manager.keyFactory(), template);
  }

  private KeyTypeManagerTestUtil() {}
}

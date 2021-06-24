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
package com.google.crypto.tink.tinkkey.internal;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplate.OutputPrefixType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.tinkkey.TinkKey;
import com.google.errorprone.annotations.Immutable;

/**
 * Wraps the proto {@code KeyData} as an implementation of a {@code TinkKey}. The underlying {@code
 * KeyData} determines whether this ProtoKey has a secret.
 *
 * <p>ProtoKey is not intended for use outside of the Tink project.
 */
@Immutable
public final class ProtoKey implements TinkKey {
  private final KeyData keyData;
  private final boolean hasSecret;
  private final OutputPrefixType outputPrefixType;

  /**
   * Constructs a ProtoKey with {@code hasSecret()} returning true if the input {@code KeyData} has
   * key material of type UNKNOWN_KEYMATERIAL, SYMMETRIC, or ASYMMETRIC_PRIVATE.
   */
  public ProtoKey(KeyData keyData, OutputPrefixType opt) {
    this.hasSecret = isSecret(keyData);
    this.keyData = keyData;
    this.outputPrefixType = opt;
  }

  private static boolean isSecret(KeyData keyData) {
    return keyData.getKeyMaterialType() == KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL
        || keyData.getKeyMaterialType() == KeyData.KeyMaterialType.SYMMETRIC
        || keyData.getKeyMaterialType() == KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  public KeyData getProtoKey() {
    return keyData;
  }

  public OutputPrefixType getOutputPrefixType() {
    return outputPrefixType;
  }

  @Override
  public boolean hasSecret() {
    return hasSecret;
  }

  /**
   * @throws UnsupportedOperationException There is currently no direct way of getting a {@code
   *     KeyTemplate} from {@code KeyData}.
   */
  @Override
  public KeyTemplate getKeyTemplate() {
    throw new UnsupportedOperationException();
  }
}

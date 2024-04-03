// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Takes an arbitrary raw HybridDecrypt and makes it a full primitive. This is a class that helps us
 * transition onto the new Keys and Configurations interface, by bringing potential user-defined
 * primitives to a common denominator with our primitives over which we have control.
 */
@Immutable
public final class LegacyFullHybridDecrypt implements HybridDecrypt {
  // We need to assume that the given HybridDecrypt is immutable. However, this assumption is
  // harmless: This class only provides "HybridDecrypt.create()" in the public API -- so as long as
  // the HybridDecrypt interface itself is not annotated with @Immutable, annotating this class
  // with @Immutable doesn't even change anything. Furthermore, once we annotate @HybridDecrypt
  // with immutable we don't need to change anything.
  @SuppressWarnings("Immutable")
  private final HybridDecrypt rawHybridDecrypt;

  @SuppressWarnings("Immutable") // We are careful and never leak this or change it.
  private final byte[] outputPrefix;

  public static HybridDecrypt create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    HybridDecrypt rawPrimitive = Registry.getPrimitive(keyData, HybridDecrypt.class);

    OutputPrefixType outputPrefixType = protoKeySerialization.getOutputPrefixType();
    byte[] outputPrefix;
    switch (outputPrefixType) {
      case RAW:
        outputPrefix = OutputPrefixUtil.EMPTY_PREFIX.toByteArray();
        break;
      case LEGACY:
      case CRUNCHY:
        outputPrefix =
            OutputPrefixUtil.getLegacyOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
        break;
      case TINK:
        outputPrefix =
            OutputPrefixUtil.getTinkOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
        break;
      default:
        throw new GeneralSecurityException("unknown output prefix type " + outputPrefixType);
    }
    return new LegacyFullHybridDecrypt(rawPrimitive, outputPrefix);
  }

  private LegacyFullHybridDecrypt(HybridDecrypt rawHybridDecrypt, byte[] outputPrefix) {
    this.rawHybridDecrypt = rawHybridDecrypt;
    this.outputPrefix = outputPrefix;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      return rawHybridDecrypt.decrypt(ciphertext, contextInfo);
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Invalid ciphertext (output prefix mismatch)");
    }
    byte[] ciphertextNoPrefix =
        Arrays.copyOfRange(ciphertext, outputPrefix.length, ciphertext.length);
    return rawHybridDecrypt.decrypt(ciphertextNoPrefix, contextInfo);
  }
}

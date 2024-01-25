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

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * Takes an arbitrary raw HybridEncrypt and makes it a full primitive. This is a class that helps us
 * transition onto the new Keys and Configurations interface, by bringing potential user-defined
 * primitives to a common denominator with our primitives over which we have control.
 */
@Immutable
public final class LegacyFullHybridEncrypt implements HybridEncrypt {
  // We need to assume that the given HybridEncrypt is immutable. However, this assumption is
  // harmless: This class only provides "HybridEncrypt.create()" in the public API -- so as long as
  // the HybridEncrypt interface itself is not annotated with @Immutable, annotating this class
  // with @Immutable doesn't even change anything. Furthermore, once we annotate @HybridEncrypt
  // with immutable we don't need to change anything.
  @SuppressWarnings("Immutable")
  private final HybridEncrypt rawHybridEncrypt;

  @SuppressWarnings("Immutable") // We are careful and never leak this or change it.
  private final byte[] outputPrefix;

  /** This method covers the cases where users created their own aead/key classes. */
  public static HybridEncrypt create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    HybridEncrypt rawPrimitive = Registry.getPrimitive(keyData, HybridEncrypt.class);

    OutputPrefixType outputPrefixType = protoKeySerialization.getOutputPrefixType();
    byte[] outputPrefix;
    switch (outputPrefixType) {
      case RAW:
        outputPrefix = new byte[] {};
        break;
      case LEGACY:
      case CRUNCHY:
        outputPrefix =
            ByteBuffer.allocate(CryptoFormat.NON_RAW_PREFIX_SIZE)
                .put((byte) 0)
                .putInt(key.getIdRequirementOrNull())
                .array();
        break;
      case TINK:
        outputPrefix =
            ByteBuffer.allocate(CryptoFormat.NON_RAW_PREFIX_SIZE)
                .put((byte) 1)
                .putInt(key.getIdRequirementOrNull())
                .array();
        break;
      default:
        throw new GeneralSecurityException("unknown output prefix type " + outputPrefixType);
    }
    return new LegacyFullHybridEncrypt(rawPrimitive, outputPrefix);
  }

  private LegacyFullHybridEncrypt(HybridEncrypt rawHybridEncrypt, byte[] outputPrefix) {
    this.rawHybridEncrypt = rawHybridEncrypt;
    this.outputPrefix = outputPrefix;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      return rawHybridEncrypt.encrypt(plaintext, contextInfo);
    }
    return Bytes.concat(outputPrefix, rawHybridEncrypt.encrypt(plaintext, contextInfo));
  }
}

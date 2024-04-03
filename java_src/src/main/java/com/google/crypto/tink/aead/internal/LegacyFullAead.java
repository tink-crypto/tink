// Copyright 2023 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.RegistryConfiguration;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Takes an arbitrary raw AEAD and makes it a full primitive. This is a class that helps us
 * transition onto the new Keys and Configurations interface, by bringing potential user-defined
 * primitives to a common denominator with our primitives over which we have control.
 */
public class LegacyFullAead implements Aead {

  private final Aead rawAead;
  private final byte[] identifier;

  /** This method covers the cases where users created their own aead/key classes. */
  public static Aead create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    Aead rawPrimitive = RegistryConfiguration.get().getLegacyPrimitive(keyData, Aead.class);

    OutputPrefixType outputPrefixType = protoKeySerialization.getOutputPrefixType();
    byte[] identifier;
    switch (outputPrefixType) {
      case RAW:
        identifier = OutputPrefixUtil.EMPTY_PREFIX.toByteArray();
        break;
      case LEGACY:
      case CRUNCHY:
        identifier =
            OutputPrefixUtil.getLegacyOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
        break;
      case TINK:
        identifier =
            OutputPrefixUtil.getTinkOutputPrefix(key.getIdRequirementOrNull()).toByteArray();
        break;
      default:
        throw new GeneralSecurityException("unknown output prefix type " + outputPrefixType);
    }

    return new LegacyFullAead(rawPrimitive, identifier);
  }

  public static Aead create(Aead rawAead, com.google.crypto.tink.util.Bytes outputPrefix) {
    return new LegacyFullAead(rawAead, outputPrefix.toByteArray());
  }

  private LegacyFullAead(Aead rawAead, byte[] identifier) {
    this.rawAead = rawAead;
    if ((identifier.length != 0) && identifier.length != CryptoFormat.NON_RAW_PREFIX_SIZE) {
      throw new IllegalArgumentException("identifier has an invalid length");
    }
    this.identifier = identifier;
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    if (identifier.length == 0) {
      return rawAead.encrypt(plaintext, associatedData);
    }
    return Bytes.concat(identifier, rawAead.encrypt(plaintext, associatedData));
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
    if (identifier.length == 0) {
      return rawAead.decrypt(ciphertext, associatedData);
    }

    if (!isPrefix(identifier, ciphertext)) {
      throw new GeneralSecurityException("wrong prefix");
    }

    return rawAead.decrypt(
        Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length),
        associatedData);
  }
}

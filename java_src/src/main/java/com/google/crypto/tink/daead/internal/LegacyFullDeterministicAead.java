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

package com.google.crypto.tink.daead.internal;

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
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
 * Takes an arbitrary raw {@link DeterministicAead} and makes it a full primitive. This is a class
 * that helps us transition onto the new Keys and Configurations interface, by bringing potential
 * user-defined primitives to a common denominator with our primitives over which we have control.
 */
public class LegacyFullDeterministicAead implements DeterministicAead {

  private final DeterministicAead rawDaead;
  private final OutputPrefixType outputPrefixType;
  private final byte[] identifier;

  /**
   * Creates a DeterministicAead full primitive from user-defined deterministic aead / key classes.
   */
  public static DeterministicAead create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();

    DeterministicAead rawPrimitive =
        RegistryConfiguration.get().getLegacyPrimitive(keyData, DeterministicAead.class);

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
        throw new GeneralSecurityException(
            "unknown output prefix type " + outputPrefixType.getNumber());
    }

    return new LegacyFullDeterministicAead(rawPrimitive, outputPrefixType, identifier);
  }

  private LegacyFullDeterministicAead(
      DeterministicAead rawDaead, OutputPrefixType outputPrefixType, byte[] identifier) {
    this.rawDaead = rawDaead;
    this.outputPrefixType = outputPrefixType;
    this.identifier = identifier;
  }

  @Override
  public byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (outputPrefixType == OutputPrefixType.RAW) {
      return rawDaead.encryptDeterministically(plaintext, associatedData);
    }
    return Bytes.concat(identifier, rawDaead.encryptDeterministically(plaintext, associatedData));
  }

  @Override
  public byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (outputPrefixType == OutputPrefixType.RAW) {
      return rawDaead.decryptDeterministically(ciphertext, associatedData);
    }

    if (!isPrefix(identifier, ciphertext)) {
      throw new GeneralSecurityException("wrong prefix");
    }
    return rawDaead.decryptDeterministically(
        Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length),
        associatedData);
  }
}

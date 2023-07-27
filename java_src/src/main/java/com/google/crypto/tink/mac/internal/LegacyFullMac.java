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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.RegistryConfiguration;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Takes an arbitrary raw Mac and makes it a full primitive.
 * This is a class that helps us transition onto the new Keys and Configurations interface,
 * by bringing potential user-defined primitives to a common denominator with our primitives over
 * which we have control.
 */
public final class LegacyFullMac implements Mac {
  // A single byte to be added to the plaintext for the legacy key type.
  private static final byte[] FORMAT_VERSION = new byte[] {0};
  static final int MIN_TAG_SIZE_IN_BYTES = 10;

  private final Mac rawMac;
  private final OutputPrefixType outputPrefixType;
  private final byte[] identifier;

  /** This method covers the cases where users created their own mac/key classes. */
  public static LegacyFullMac create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    Mac rawPrimitive = RegistryConfiguration.get().getLegacyPrimitive(keyData, Mac.class);

    OutputPrefixType outputPrefixType = protoKeySerialization.getOutputPrefixType();
    byte[] outputPrefix;
    switch (outputPrefixType) {
      case RAW:
        outputPrefix = new byte[] {};
        break;
      case LEGACY:
      case CRUNCHY:
        outputPrefix =
            ByteBuffer.allocate(5).put((byte) 0).putInt(key.getIdRequirementOrNull()).array();
        break;
      case TINK:
        outputPrefix =
            ByteBuffer.allocate(5).put((byte) 1).putInt(key.getIdRequirementOrNull()).array();
        break;
      default:
        throw new GeneralSecurityException("unknown output prefix type");
    }
    return new LegacyFullMac(rawPrimitive, outputPrefixType, outputPrefix);
  }

  private LegacyFullMac(Mac rawMac, OutputPrefixType outputPrefixType, byte[] identifier) {
    this.rawMac = rawMac;
    this.outputPrefixType = outputPrefixType;
    this.identifier = identifier;
  }

  @Override
  public byte[] computeMac(byte[] data) throws GeneralSecurityException {
    byte[] data2 = data;
    if (outputPrefixType.equals(OutputPrefixType.LEGACY)) {
      data2 = Bytes.concat(data, FORMAT_VERSION);
    }
    return Bytes.concat(identifier, rawMac.computeMac(data2));
  }

  @Override
  public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
    if (mac.length < MIN_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag too short");
    }

    byte[] data2 = data;
    if (outputPrefixType.equals(OutputPrefixType.LEGACY)) {
      data2 = Bytes.concat(data, FORMAT_VERSION);
    }

    byte[] prefix = new byte[0];
    byte[] macNoPrefix = mac;
    if (!outputPrefixType.equals(OutputPrefixType.RAW)) {
      prefix = Arrays.copyOf(mac, CryptoFormat.NON_RAW_PREFIX_SIZE);
      macNoPrefix = Arrays.copyOfRange(mac, CryptoFormat.NON_RAW_PREFIX_SIZE, mac.length);
    }

    if (!Arrays.equals(identifier, prefix)) {
      throw new GeneralSecurityException("wrong prefix");
    }

    rawMac.verifyMac(macNoPrefix, data2);
  }
}

// Copyright 2024 Google LLC
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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Takes an arbitrary raw PublicKeySign from the registry and creates a full PublicKeySign out of
 * it.
 */
@Immutable
public final class LegacyFullSign implements PublicKeySign {
  /** Creates the full primitive corresponding to the key. */
  public static PublicKeySign create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    PublicKeySign rawSigner = Registry.getPrimitive(keyData, PublicKeySign.class);

    return new LegacyFullSign(
        rawSigner,
        LegacyFullVerify.getOutputPrefix(protoKeySerialization),
        LegacyFullVerify.getMessageSuffix(protoKeySerialization));
  }

  private LegacyFullSign(PublicKeySign rawSigner, byte[] outputPrefix, byte[] messageSuffix) {
    this.rawSigner = rawSigner;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  @SuppressWarnings("Immutable")
  private final PublicKeySign rawSigner;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @Override
  public byte[] sign(byte[] data) throws GeneralSecurityException {
    byte[] signature;
    if (messageSuffix.length == 0) {
      signature = rawSigner.sign(data);
    } else {
      signature = rawSigner.sign(Bytes.concat(data, messageSuffix));
    }
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}

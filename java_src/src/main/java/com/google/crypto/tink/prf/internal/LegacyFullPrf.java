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

package com.google.crypto.tink.prf.internal;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.proto.KeyData;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Takes an arbitrary raw Prf and makes it a full primitive. ("Full" doesn't make much difference
 * in case of PRFs but we keep the name for consistency with the other primitives.)
 * This is a class that helps us transition onto the new Keys and Configurations interface,
 * by bringing potential user-defined primitives to a common denominator with our primitives over
 * which we have control.
 */
@Immutable
public class LegacyFullPrf implements Prf {

  private final Prf rawPrf;

  /** This method covers the cases where users created their own prf/key classes. */
  public static Prf create(LegacyProtoKey key) throws GeneralSecurityException {
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    return new LegacyFullPrf(Registry.getPrimitive(keyData, Prf.class));
  }

  private LegacyFullPrf(Prf rawPrf) {
    this.rawPrf = rawPrf;
  }

  @Override
  public byte[] compute(byte[] input, int outputLength) throws GeneralSecurityException {
    return rawPrf.compute(input, outputLength);
  }
}

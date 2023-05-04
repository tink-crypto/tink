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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.crypto.tink.internal.Util.UTF_8;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrivilegedRegistry;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.errorprone.annotations.Immutable;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * An implementation of {@link KeysetDeriver}, which uses a PRF and the Tink registry to derive a
 * {@link com.google.crypto.tink.KeysetHandle}.
 */
@Immutable
public class PrfBasedDeriver implements KeysetDeriver {
  private PrfBasedDeriver(KeyData streamingPrfKey, KeyTemplate derivedKeyTemplate) {
    this.streamingPrfKey = streamingPrfKey;
    this.derivedKeyTemplate = derivedKeyTemplate;
  }

  public static PrfBasedDeriver create(KeyData streamingPrfKey, KeyTemplate derivedKeyTemplate)
      throws GeneralSecurityException {
    // Validate {@code streamingPrfKey} and {@code derivedKeyTemplate}.
    StreamingPrf prf = Registry.getPrimitive(streamingPrfKey, StreamingPrf.class);
    KeyData unused =
        PrivilegedRegistry.deriveKey(derivedKeyTemplate, prf.computePrf("s".getBytes(UTF_8)));

    return new PrfBasedDeriver(streamingPrfKey, derivedKeyTemplate);
  }

  private final KeyData streamingPrfKey;
  private final KeyTemplate derivedKeyTemplate;

  @Override
  public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
    StreamingPrf prf = Registry.getPrimitive(streamingPrfKey, StreamingPrf.class);
    InputStream randomness = prf.computePrf(salt);
    KeyData keyData = PrivilegedRegistry.deriveKey(derivedKeyTemplate, randomness);
    Keyset.Key key =
        Keyset.Key.newBuilder()
            .setKeyData(keyData)
            .setStatus(KeyStatusType.UNKNOWN_STATUS)
            .setKeyId(0)
            .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX)
            .build();
    return TinkProtoKeysetFormat.parseKeyset(
        Keyset.newBuilder().addKey(key).setPrimaryKeyId(0).build().toByteArray(),
        InsecureSecretKeyAccess.get());
  }
}

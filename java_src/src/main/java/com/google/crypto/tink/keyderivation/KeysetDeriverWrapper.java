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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.Keyset;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * KeysetDeriverWrapper is the implementation of PrimitiveWrapper for the KeysetDeriver primitive.
 *
 * <p>The wrapper derives a key from each key in a keyset, and returns the resulting keys as a new
 * keyset. Each of the derived keys inherits key_id, status, and output_prefix_type from the key
 * from which it was derived.
 */
public class KeysetDeriverWrapper implements PrimitiveWrapper<KeysetDeriver, KeysetDeriver> {

  private static final KeysetDeriverWrapper WRAPPER = new KeysetDeriverWrapper();

  private static void validate(PrimitiveSet<KeysetDeriver> primitiveSet)
      throws GeneralSecurityException {
    if (primitiveSet.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedKeysetDeriver implements KeysetDeriver {
    @SuppressWarnings("Immutable")
    private final PrimitiveSet<KeysetDeriver> primitiveSet;

    private WrappedKeysetDeriver(PrimitiveSet<KeysetDeriver> primitiveSet) {
      this.primitiveSet = primitiveSet;
    }

    private static KeyData deriveAndGetKeyData(byte[] salt, KeysetDeriver deriver)
        throws GeneralSecurityException {
      KeysetHandle keysetHandle = deriver.deriveKeyset(salt);
      Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
      if (keyset.getKeyCount() != 1) {
        throw new GeneralSecurityException(
            "Wrapped Deriver must create a keyset with exactly one KeyData");
      }
      return keyset.getKey(0).getKeyData();
    }

    @Override
    public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
      Keyset.Builder builder = Keyset.newBuilder();
      for (PrimitiveSet.Entry<KeysetDeriver> entry : primitiveSet.getAllInKeysetOrder()) {
        builder.addKey(
            Keyset.Key.newBuilder()
                .setKeyData(deriveAndGetKeyData(salt, entry.getPrimitive()))
                .setStatus(entry.getStatus())
                .setOutputPrefixType(entry.getOutputPrefixType())
                .setKeyId(entry.getKeyId()));
      }
      builder.setPrimaryKeyId(primitiveSet.getPrimary().getKeyId());
      return TinkProtoKeysetFormat.parseKeyset(
          builder.build().toByteArray(), InsecureSecretKeyAccess.get());
    }
  }

  KeysetDeriverWrapper() {}

  @Override
  public KeysetDeriver wrap(final PrimitiveSet<KeysetDeriver> primitiveSet)
      throws GeneralSecurityException {
    validate(primitiveSet);
    return new WrappedKeysetDeriver(primitiveSet);
  }

  @Override
  public Class<KeysetDeriver> getPrimitiveClass() {
    return KeysetDeriver.class;
  }

  @Override
  public Class<KeysetDeriver> getInputPrimitiveClass() {
    return KeysetDeriver.class;
  }

  /** Registers this wrapper with Tink, allowing to use the primitive. */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(WRAPPER);
  }
}

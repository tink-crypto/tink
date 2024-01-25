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

package com.google.crypto.tink.keyderivation.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/** */
public final class KeysetDeriverWrapper implements PrimitiveWrapper<KeyDeriver, KeysetDeriver> {

  private static final KeysetDeriverWrapper WRAPPER = new KeysetDeriverWrapper();

  private static void validate(PrimitiveSet<KeyDeriver> primitiveSet)
      throws GeneralSecurityException {
    if (primitiveSet.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
  }

  @Immutable
  private static class WrappedKeysetDeriver implements KeysetDeriver {
    @SuppressWarnings("Immutable")
    private final PrimitiveSet<KeyDeriver> primitiveSet;

    private WrappedKeysetDeriver(PrimitiveSet<KeyDeriver> primitiveSet) {
      this.primitiveSet = primitiveSet;
    }

    private static KeysetHandle.Builder.Entry deriveAndGetEntry(
        byte[] salt, PrimitiveSet.Entry<KeyDeriver> entry, int primaryKeyId)
        throws GeneralSecurityException {
      KeyDeriver deriver = entry.getFullPrimitive();
      if (deriver == null) {
        throw new GeneralSecurityException(
            "Primitive set has non-full primitives -- this is probably a bug");
      }
      Key key = deriver.deriveKey(salt);
      KeysetHandle.Builder.Entry result = KeysetHandle.importKey(key);
      result.withFixedId(entry.getKeyId());
      if (entry.getKeyId() == primaryKeyId) {
        result.makePrimary();
      }
      return result;
    }

    @Override
    public KeysetHandle deriveKeyset(byte[] salt) throws GeneralSecurityException {
      KeysetHandle.Builder builder = KeysetHandle.newBuilder();
      for (PrimitiveSet.Entry<KeyDeriver> entry : primitiveSet.getAllInKeysetOrder()) {
        builder.addEntry(deriveAndGetEntry(salt, entry, primitiveSet.getPrimary().getKeyId()));
      }
      return builder.build();
    }
  }

  KeysetDeriverWrapper() {}

  @Override
  public KeysetDeriver wrap(final PrimitiveSet<KeyDeriver> primitiveSet)
      throws GeneralSecurityException {
    validate(primitiveSet);
    return new WrappedKeysetDeriver(primitiveSet);
  }

  @Override
  public Class<KeysetDeriver> getPrimitiveClass() {
    return KeysetDeriver.class;
  }

  @Override
  public Class<KeyDeriver> getInputPrimitiveClass() {
    return KeyDeriver.class;
  }

  /** Registers this wrapper with Tink, allowing to use the primitive. */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(WRAPPER);
  }
}

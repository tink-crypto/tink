// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<PublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
class PublicKeySignWrapper implements PrimitiveWrapper<PublicKeySign> {
  private static class WrappedPublicKeySign implements PublicKeySign {
    private final PrimitiveSet<PublicKeySign> primitives;

    public WrappedPublicKeySign(final PrimitiveSet<PublicKeySign> primitives) {
      this.primitives = primitives;
    }

    @Override
    public byte[] sign(final byte[] data) throws GeneralSecurityException {
      if (primitives.getPrimary().getOutputPrefixType().equals(OutputPrefixType.LEGACY)) {
        byte[] formatVersion = new byte[] {CryptoFormat.LEGACY_START_BYTE};
        return Bytes.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().sign(Bytes.concat(data, formatVersion)));
      }
      return Bytes.concat(
          primitives.getPrimary().getIdentifier(),
          primitives.getPrimary().getPrimitive().sign(data));
    }
  }

  @Override
  public PublicKeySign wrap(final PrimitiveSet<PublicKeySign> primitives) {
    return new WrappedPublicKeySign(primitives);
  }

  @Override
  public Class<PublicKeySign> getPrimitiveClass() {
    return PublicKeySign.class;
  }
}

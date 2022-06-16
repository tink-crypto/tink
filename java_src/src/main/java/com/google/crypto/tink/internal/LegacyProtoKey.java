// Copyright 2022 Google LLC
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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyFormat;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.subtle.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Implements a Key for legacy types where no actual parser is present. */
@Immutable
public final class LegacyProtoKey extends Key {
  private final ProtoKeySerialization serialization;

  private static void throwIfMissingAccess(
      ProtoKeySerialization protoKeySerialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    switch (protoKeySerialization.getKeyMaterialType()) {
      case SYMMETRIC:
      case ASYMMETRIC_PRIVATE:
        SecretKeyAccess.requireAccess(access);
        break;
      default:
    }
  }

  /**
   * Creates a new LegacyProtoKey object.
   *
   * <p>Access is required for SYMMETRIC and ASYMMETRIC_PRIVATE key material types.
   */
  public LegacyProtoKey(ProtoKeySerialization serialization, @Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    throwIfMissingAccess(serialization, access);
    this.serialization = serialization;
  }

  /**
   * Returns true if we are sure that the other key is the same.
   *
   * <p>Due to the fact that proto key serialization isn't guaranteed to be deterministic, this
   * isn't guaranteed to be true in case two serializations are actually the same. This shouldn't be
   * a problem: the use of key equality is that one can implement keyset equality, which is useful
   * when one wants the guarantee that two keysets are the same (for example, when one changes the
   * source of the keyset from disk to a remotely stored keyset). Since the only thing which can
   * happen is that we falsely return "false", this can then be solved in debugging. (The
   * alternative would be to throw an UnsupportedOperationException while we add the real
   * implementations of keys)
   */
  @Override
  public boolean equalsKey(Key key) {
    if (!(key instanceof LegacyProtoKey)) {
      return false;
    }
    ProtoKeySerialization other = ((LegacyProtoKey) key).serialization;

    if (!other.getOutputPrefixType().equals(serialization.getOutputPrefixType())) {
      return false;
    }
    if (!other.getKeyMaterialType().equals(serialization.getKeyMaterialType())) {
      return false;
    }
    if (!other.getTypeUrl().equals(serialization.getTypeUrl())) {
      return false;
    }
    if (!Objects.equals(other.getIdRequirementOrNull(), serialization.getIdRequirementOrNull())) {
      return false;
    }
    return Bytes.equal(serialization.getValue().toByteArray(), other.getValue().toByteArray());
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return serialization.getIdRequirementOrNull();
  }

  /**
   * Returns the protokeyserialization with which this object was created.
   *
   * <p>Access is required for SYMMETRIC and ASYMMETRIC_PRIVATE key material types.
   */
  public ProtoKeySerialization getSerialization(@Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    throwIfMissingAccess(serialization, access);
    return serialization;
  }

  /** Unsupported. */
  @Override
  public KeyFormat getKeyFormat() {
    throw new UnsupportedOperationException("Cannot get key format on LegacyProtoKey");
  }
}

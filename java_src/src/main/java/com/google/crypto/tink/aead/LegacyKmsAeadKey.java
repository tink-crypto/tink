// Copyright 2023 Google Inc.
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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.Bytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes an Aead backed by a KMS.
 *
 * <p>The KMS is specified by {@code getParameters().getKeyUri()}. When creating an Aead from this
 * object, Tink looks an {@link com.google.crypto.tink.KmsClient} in the global table of {@link
 * com.google.crypto.tink.KmsClients}. This means that the key is inappropriate in cases where there
 * are multiple KMS backends or multiple credentials in a binary. Because of this, we recommend to
 * create the {@link Aead} directly from the KmsClient you need.
 */
public class LegacyKmsAeadKey extends AeadKey {
  private final LegacyKmsAeadParameters parameters;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private LegacyKmsAeadKey(
      LegacyKmsAeadParameters parameters, Bytes outputPrefix, @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  public static LegacyKmsAeadKey create(
      LegacyKmsAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Bytes outputPrefix;
    if (parameters.variant() == LegacyKmsAeadParameters.Variant.TINK) {
      if (idRequirement == null) {
        throw new GeneralSecurityException(
            "For given Variant TINK the value of idRequirement must be non-null");
      }
      outputPrefix =
          Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
    } else if (parameters.variant() == LegacyKmsAeadParameters.Variant.NO_PREFIX) {
      if (idRequirement != null) {
        throw new GeneralSecurityException(
            "For given Variant NO_PREFIX the value of idRequirement must be null");
      }
      outputPrefix = Bytes.copyFrom(new byte[] {});
    } else {
      throw new GeneralSecurityException("Unknown Variant: " + parameters.variant());
    }
    return new LegacyKmsAeadKey(parameters, outputPrefix, idRequirement);
  }

  public static LegacyKmsAeadKey create(LegacyKmsAeadParameters parameters)
      throws GeneralSecurityException {
    return create(parameters, null);
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public LegacyKmsAeadParameters getParameters() {
    return parameters;
  }

  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof LegacyKmsAeadKey)) {
      return false;
    }
    LegacyKmsAeadKey that = (LegacyKmsAeadKey) o;
    return that.parameters.equals(parameters) && Objects.equals(that.idRequirement, idRequirement);
  }
}

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
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes an EnvelopeAead backed by a KMS.
 *
 * <p>Usage of this key type is not recommended. Instead, we recommend to implement the idea of this
 * class manually:
 *
 * <ol>
 *   <li>Create an remote {@link com.google.crypto.tink.Aead} object for your KMS with an
 *       appropriate Tink extension (typically using a subclass of {@link
 *       com.google.crypto.tink.KmsClient}).
 *   <li>Create an envelope AEAD with {@link com.google.crypto.tink.aead.KmsEnvelopeAead#create}.
 * </ol>
 *
 * See {@link LegacyKmsEnvelopeParameters} for known issues.
 */
public class LegacyKmsEnvelopeAeadKey extends AeadKey {
  private final LegacyKmsEnvelopeAeadParameters parameters;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private LegacyKmsEnvelopeAeadKey(
      LegacyKmsEnvelopeAeadParameters parameters,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  public static LegacyKmsEnvelopeAeadKey create(
      LegacyKmsEnvelopeAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Bytes outputPrefix;
    if (parameters.getVariant() == LegacyKmsEnvelopeAeadParameters.Variant.NO_PREFIX) {
      if (idRequirement != null) {
        throw new GeneralSecurityException(
            "For given Variant NO_PREFIX the value of idRequirement must be null");
      }
      outputPrefix = OutputPrefixUtil.EMPTY_PREFIX;
    } else if (parameters.getVariant() == LegacyKmsEnvelopeAeadParameters.Variant.TINK) {
      if (idRequirement == null) {
        throw new GeneralSecurityException(
            "For given Variant TINK the value of idRequirement must be non-null");
      }
      outputPrefix = OutputPrefixUtil.getTinkOutputPrefix(idRequirement);
    } else {
      throw new GeneralSecurityException("Unknown Variant: " + parameters.getVariant());
    }
    return new LegacyKmsEnvelopeAeadKey(parameters, outputPrefix, idRequirement);
  }

  public static LegacyKmsEnvelopeAeadKey create(LegacyKmsEnvelopeAeadParameters parameters)
      throws GeneralSecurityException {
    return create(parameters, null);
  }

  @Override
  public Bytes getOutputPrefix() {
    return this.outputPrefix;
  }

  @Override
  public LegacyKmsEnvelopeAeadParameters getParameters() {
    return parameters;
  }

  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof LegacyKmsEnvelopeAeadKey)) {
      return false;
    }
    LegacyKmsEnvelopeAeadKey that = (LegacyKmsEnvelopeAeadKey) o;
    return that.parameters.equals(parameters) && Objects.equals(that.idRequirement, idRequirement);
  }
}

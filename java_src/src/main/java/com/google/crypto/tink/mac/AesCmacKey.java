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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents a key computing AES-CMAC.
 *
 * <p>AES-CMAC is specified in RFC 4493. Tink supports AES-CMAC with keys of length 32 bytes (256
 * bits) only.
 */
public final class AesCmacKey extends MacKey {
  private final AesCmacParameters parameters;
  private final SecretBytes aesKeyBytes;
  @Nullable private final Integer idRequirement;

  private AesCmacKey(
      AesCmacParameters parameters, SecretBytes aesKeyBytes, @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.aesKeyBytes = aesKeyBytes;
    this.idRequirement = idRequirement;
  }

  /** Creates a new AES-CMAC key with an empty prefix. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static AesCmacKey create(AesCmacParameters parameters, SecretBytes aesKey)
      throws GeneralSecurityException {
    // The only check on the key size since it's verified during AesCmacParameter creation.
    if (parameters.getKeySizeBytes() != aesKey.size()) {
      throw new GeneralSecurityException("Key size mismatch");
    }

    if (parameters.hasIdRequirement()) {
      throw new GeneralSecurityException(
          "Must use createForKeyset for parameters with ID requirement");
    }

    return new AesCmacKey(parameters, aesKey, null);
  }

  /**
   * Creates a new AES-CMAC key for use in a keyset.
   *
   * <p>If the format specifies a variant which uses a prefix, the id is used to compute this
   * prefix.
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static AesCmacKey createForKeyset(
      AesCmacParameters parameters, SecretBytes aesKeyBytes, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    // The only check on the key size since it's verified during AesCmacParameter creation.
    if (parameters.getKeySizeBytes() != aesKeyBytes.size()) {
      throw new GeneralSecurityException("Key size mismatch");
    }

    if (parameters.hasIdRequirement() && idRequirement == null) {
      throw new GeneralSecurityException(
          "Cannot create key without ID requirement with format with ID requirement");
    }

    if (!parameters.hasIdRequirement() && idRequirement != null) {
      throw new GeneralSecurityException(
          "Cannot create key with ID requirement with format without ID requirement");
    }

    return new AesCmacKey(parameters, aesKeyBytes, idRequirement);
  }

  /** Returns the underlying AES key. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getAesKey() {
    return aesKeyBytes;
  }

  @Override
  public Bytes getOutputPrefix() {
    if (parameters.getVariant() == AesCmacParameters.Variant.NO_PREFIX) {
      return Bytes.copyFrom(new byte[] {});
    }
    if (parameters.getVariant() == AesCmacParameters.Variant.LEGACY
        || parameters.getVariant() == AesCmacParameters.Variant.CRUNCHY) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
    }
    if (parameters.getVariant() == AesCmacParameters.Variant.TINK) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
    }
    throw new IllegalStateException(
        "Unknown AesCmacParameters.Variant: " + parameters.getVariant());
  }

  @Override
  public AesCmacParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof AesCmacKey)) {
      return false;
    }
    AesCmacKey that = (AesCmacKey) o;
    return that.parameters.equals(parameters)
        && that.aesKeyBytes.equalsSecretBytes(aesKeyBytes)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}

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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link LegacyKmsEnvelopeAeadKey}.
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
 * <H1>Known Issues</h1>
 *
 * <H2>Global registration</h2>
 *
 * If a user uses a {@code LegacyKmsEnvelopeAeadKey}, when the corresponding {@code Aead} is
 * created, Tink looks up the {@code KmsClient} in a global registry. This registry needs to store
 * all the credentials and all the information. This is inappropriate in many situations.
 *
 * <h2>Ciphertext format</h2>
 *
 * The ciphertext format does not encode the key type of the key used. This can lead to unexpected
 * results if a user changes the {@code dekParametersForNewKeys} or the {@code dekParsingStrategy}
 * for the same remote key. In more details, the ciphertext contains a Tink key proto of newly
 * generated key, but not the type URL. This means that if a user reuses the same remote Key with a
 * different key type, it will be parsed with the wrong one.
 *
 * <p>Also, Tink does note compare the parameters of the parsed key with the parameters specified in
 * {@code dekParametersForNewKeys}. For example, if the {@code dekParametersForNewKeys} is specified
 * as AES_128_GCM in one binary, and AES_256_GCM in another binary, communication between the
 * binaries succeeds in both directions.
 *
 * <h2>Ciphertext malleability</h2>
 *
 * <p>Some KMS have malleable ciphertexts. This means that the Aeads corresponding to these keys may
 * be malleable. See https://developers.google.com/tink/issues/envelope-aead-malleability
 */
public final class LegacyKmsEnvelopeAeadParameters extends AeadParameters {

  /**
   * Specifies how the DEK in received ciphertexts are parsed.
   *
   * <p>See section "Ciphertext format" above for a discussion of this.
   */
  @Immutable
  public static final class DekParsingStrategy {
    /** When parsing, assume that the ciphertext was encrypted with AES GCM. */
    public static final DekParsingStrategy ASSUME_AES_GCM =
        new DekParsingStrategy("ASSUME_AES_GCM");

    /** When parsing, assume that the ciphertext was encrypted with XChaCha20-Poly1305. */
    public static final DekParsingStrategy ASSUME_XCHACHA20POLY1305 =
        new DekParsingStrategy("ASSUME_XCHACHA20POLY1305");

    /** When parsing, assume that the ciphertext was encrypted with ChaCha20-Poly1305. */
    public static final DekParsingStrategy ASSUME_CHACHA20POLY1305 =
        new DekParsingStrategy("ASSUME_CHACHA20POLY1305");

    /** When parsing, assume that the ciphertext was encrypted with AES CTR HMAC. */
    public static final DekParsingStrategy ASSUME_AES_CTR_HMAC =
        new DekParsingStrategy("ASSUME_AES_CTR_HMAC");

    /** When parsing, assume that the ciphertext was encrypted with AES EAX. */
    public static final DekParsingStrategy ASSUME_AES_EAX =
        new DekParsingStrategy("ASSUME_AES_EAX");

    /** When parsing, assume that the ciphertext was encrypted with AES GCM SIV. */
    public static final DekParsingStrategy ASSUME_AES_GCM_SIV =
        new DekParsingStrategy("ASSUME_AES_GCM_SIV");

    private final String name;

    private DekParsingStrategy(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private final String kekUri;
  private final DekParsingStrategy dekParsingStrategy;
  private final AeadParameters dekParametersForNewKeys;

  private LegacyKmsEnvelopeAeadParameters(
      String kekUri,
      DekParsingStrategy dekParsingStrategy,
      AeadParameters dekParametersForNewKeys) {
    this.kekUri = kekUri;
    this.dekParsingStrategy = dekParsingStrategy;
    this.dekParametersForNewKeys = dekParametersForNewKeys;
  }

  /** Builder for {@link LegacyKmsEnvelopeAeadParameters}. */
  public static class Builder {
    @Nullable private String kekUri;
    @Nullable private DekParsingStrategy dekParsingStrategy;
    @Nullable private AeadParameters dekParametersForNewKeys;

    private Builder() {}

    /**
     * Sets the URI of the KMS to be used.
     *
     * <p>The KMS will be used to encrypt the DEK key as an AEAD.
     */
    public Builder setKekUri(String kekUri) {
      this.kekUri = kekUri;
      return this;
    }

    public Builder setDekParsingStrategy(DekParsingStrategy dekParsingStrategy) {
      this.dekParsingStrategy = dekParsingStrategy;
      return this;
    }

    public Builder setDekParametersForNewKeys(AeadParameters aeadParameters) {
      this.dekParametersForNewKeys = aeadParameters;
      return this;
    }

    private static boolean parsingStrategyAllowed(
        DekParsingStrategy parsingStrategy, AeadParameters aeadParameters) {
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_AES_GCM)
          && (aeadParameters instanceof AesGcmParameters)) {
        return true;
      }
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_CHACHA20POLY1305)
          && (aeadParameters instanceof ChaCha20Poly1305Parameters)) {
        return true;
      }
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
          && (aeadParameters instanceof XChaCha20Poly1305Parameters)) {
        return true;
      }
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_AES_CTR_HMAC)
          && (aeadParameters instanceof AesCtrHmacAeadParameters)) {
        return true;
      }
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_AES_EAX)
          && (aeadParameters instanceof AesEaxParameters)) {
        return true;
      }
      if (parsingStrategy.equals(DekParsingStrategy.ASSUME_AES_GCM_SIV)
          && (aeadParameters instanceof AesGcmSivParameters)) {
        return true;
      }
      return false;
    }

    /** Builds the LegacyKmsEnvelopeAeadParameters. */
    public LegacyKmsEnvelopeAeadParameters build() throws GeneralSecurityException {
      if (kekUri == null) {
        throw new GeneralSecurityException("kekUri must be set");
      }
      if (dekParsingStrategy == null) {
        throw new GeneralSecurityException("dekParsingStrategy must be set");
      }
      if (dekParametersForNewKeys == null) {
        throw new GeneralSecurityException("dekParametersForNewKeys must be set");
      }
      if (dekParametersForNewKeys.hasIdRequirement()) {
        throw new GeneralSecurityException(
            "dekParametersForNewKeys must note have ID Requirements");
      }
      if (!parsingStrategyAllowed(dekParsingStrategy, dekParametersForNewKeys)) {
        throw new GeneralSecurityException(
            "Cannot use parsing strategy "
                + dekParsingStrategy.toString()
                + " when new keys are picked according to "
                + dekParametersForNewKeys
                + ".");
      }

      return new LegacyKmsEnvelopeAeadParameters(
          kekUri, dekParsingStrategy, dekParametersForNewKeys);
    }
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  /** Returns the URI with the key of the remote AEAD used. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public String getKekUri() {
    return kekUri;
  }

  @Override
  public boolean hasIdRequirement() {
    return false;
  }

  /**
   * Returns the type URL which is used when parsing encrypted keys.
   *
   * <p>See "Known Issues" section above.
   */
  public DekParsingStrategy getDekParsingStrategy() {
    return dekParsingStrategy;
  }

  /** Parameters used when creating new keys. */
  public AeadParameters getDekParametersForNewKeys() {
    return dekParametersForNewKeys;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyKmsEnvelopeAeadParameters)) {
      return false;
    }
    LegacyKmsEnvelopeAeadParameters that = (LegacyKmsEnvelopeAeadParameters) o;
    return that.dekParsingStrategy.equals(dekParsingStrategy)
        && that.dekParametersForNewKeys.equals(dekParametersForNewKeys)
        && that.kekUri.equals(kekUri);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        LegacyKmsEnvelopeAeadParameters.class, kekUri, dekParsingStrategy, dekParametersForNewKeys);
  }

  @Override
  public String toString() {
    return "LegacyKmsEnvelopeAead Parameters (kekUri: "
        + kekUri
        + ", "
        + "dekParsingStrategy: "
        + dekParsingStrategy
        + ", "
        + "dekParametersForNewKeys: "
        + dekParametersForNewKeys
        + ")";
  }
}

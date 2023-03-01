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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;

/**
 * Represents a StreamingAead functions.
 *
 * <p>See https://developers.devsite.corp.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming.
 */
public final class AesGcmHkdfStreamingKey extends StreamingAeadKey {
  private final AesGcmHkdfStreamingParameters parameters;
  private final SecretBytes initialKeymaterial;

  private AesGcmHkdfStreamingKey(
      AesGcmHkdfStreamingParameters parameters, SecretBytes initialKeymaterial) {
    this.parameters = parameters;
    this.initialKeymaterial = initialKeymaterial;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static AesGcmHkdfStreamingKey create(
      AesGcmHkdfStreamingParameters parameters, SecretBytes initialKeymaterial)
      throws GeneralSecurityException {

    if (parameters.getKeySizeBytes() != initialKeymaterial.size()) {
      throw new GeneralSecurityException("Key size mismatch");
    }
    return new AesGcmHkdfStreamingKey(parameters, initialKeymaterial);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getInitialKeyMaterial() {
    return initialKeymaterial;
  }

  @Override
  public AesGcmHkdfStreamingParameters getParameters() {
    return parameters;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof AesGcmHkdfStreamingKey)) {
      return false;
    }
    AesGcmHkdfStreamingKey that = (AesGcmHkdfStreamingKey) o;
    return that.parameters.equals(parameters)
        && that.initialKeymaterial.equalsSecretBytes(initialKeymaterial);
  }
}

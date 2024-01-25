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

package com.google.tink1to2;

import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.daead.DeterministicAeadKeyTemplates;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.hybrid.PredefinedHybridParameters;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;
import com.google.errorprone.refaster.annotation.AfterTemplate;
import com.google.errorprone.refaster.annotation.BeforeTemplate;
import java.io.IOException;
import java.security.GeneralSecurityException;

// We keep all changes in one file due to https://github.com/google/error-prone/issues/552
final class AllChanges {
  class CleanupKeysetHandleReaderNoSecret {
    @BeforeTemplate
    public KeysetHandle beforeTemplate(byte[] b) throws GeneralSecurityException {
      return KeysetHandle.readNoSecret(b);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate(byte[] b) throws GeneralSecurityException {
      return TinkProtoKeysetFormat.parseKeysetWithoutSecret(b);
    }
  }

  /**
   * If users first create a binary keyset reader from a byte[], then call readNoSecret, we can
   * simply call the new function directly without any parsing.
   */
  class CleanupKeysetHandleReadNoSecretReaderWithBinaryReader {
    @BeforeTemplate
    public KeysetHandle beforeTemplate(byte[] bytes) throws GeneralSecurityException, IOException {
      return KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(bytes));
    }

    @AfterTemplate
    public KeysetHandle afterTemplate(byte[] bytes) throws GeneralSecurityException, IOException {
      return TinkProtoKeysetFormat.parseKeysetWithoutSecret(bytes);
    }
  }

  class HMAC_SHA256_128BITTAG {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
    }
  }

  class HMAC_SHA256_256BITTAG {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_256BITTAG);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_256BITTAG);
    }
  }

  class HMAC_SHA512_256BITTAG {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_256BITTAG);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA512_256BITTAG);
    }
  }

  class HMAC_SHA512_512BITTAG {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_512BITTAG);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA512_512BITTAG);
    }
  }

  class AES_CMAC {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(MacKeyTemplates.AES_CMAC);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedMacParameters.AES_CMAC);
    }
  }

  class AES128_GCM {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM);
    }
  }

  class AES256_GCM {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES256_GCM);
    }
  }

  class AES128_EAX {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES128_EAX);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX);
    }
  }

  class AES256_EAX {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES256_EAX);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES256_EAX);
    }
  }

  class AES128_CTR_HMAC_SHA256 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256);
    }
  }

  class AES256_CTR_HMAC_SHA256 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.AES256_CTR_HMAC_SHA256);
    }
  }

  class CHACHA20_POLY1305 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.CHACHA20_POLY1305);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.CHACHA20_POLY1305);
    }
  }

  class XCHACHA20_POLY1305 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(AeadKeyTemplates.XCHACHA20_POLY1305);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedAeadParameters.XCHACHA20_POLY1305);
    }
  }

  class AES256_SIV {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(DeterministicAeadKeyTemplates.AES256_SIV);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedDeterministicAeadParameters.AES256_SIV);
    }
  }

  class AES128_CTR_HMAC_SHA256_4KB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_4KB);
    }
  }

  class AES128_CTR_HMAC_SHA256_1MB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_1MB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_1MB);
    }
  }

  class AES256_CTR_HMAC_SHA256_4KB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_4KB);
    }
  }

  class AES256_CTR_HMAC_SHA256_1MB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_1MB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_1MB);
    }
  }

  class AES128_GCM_HKDF_4KB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB);
    }
  }

  class AES128_GCM_HKDF_1MB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_1MB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES128_GCM_HKDF_1MB);
    }
  }

  class AES256_GCM_HKDF_4KB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES256_GCM_HKDF_4KB);
    }
  }

  class AES256_GCM_HKDF_1MB {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_1MB);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB);
    }
  }

  class ECDSA_P256 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256);
    }
  }

  class ECDSA_P384 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P384);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P384);
    }
  }

  class ECDSA_P521 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P521);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P521);
    }
  }

  class ECDSA_P256_IEEE_P1363 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256_IEEE_P1363);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363);
    }
  }

  class ECDSA_P384_IEEE_P1363 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P384_IEEE_P1363);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P384_IEEE_P1363);
    }
  }

  class ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    }
  }

  class ECDSA_P521_IEEE_P1363 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P521_IEEE_P1363);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P521_IEEE_P1363);
    }
  }

  class ED25519 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ED25519);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519);
    }
  }

  class ED25519WithRawOutput {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.ED25519WithRawOutput);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519WithRawOutput);
    }
  }

  class RSA_SSA_PKCS1_3072_SHA256_F4 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4);
    }
  }

  class RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          SignatureKeyTemplates.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX);
    }
  }

  class RSA_SSA_PKCS1_4096_SHA512_F4 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.RSA_SSA_PKCS1_4096_SHA512_F4);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(PredefinedSignatureParameters.RSA_SSA_PKCS1_4096_SHA512_F4);
    }
  }

  class RSA_SSA_PSS_3072_SHA256_SHA256_32_F4 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4);
    }
  }

  class RSA_SSA_PSS_4096_SHA512_SHA512_64_F4 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(SignatureKeyTemplates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedSignatureParameters.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4);
    }
  }

  class ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
    }
  }

  class ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedHybridParameters
              .ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX);
    }
  }

  class ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 {
    @BeforeTemplate
    public KeysetHandle beforeTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate() throws GeneralSecurityException {
      return KeysetHandle.generateNew(
          PredefinedHybridParameters.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256);
    }
  }
}

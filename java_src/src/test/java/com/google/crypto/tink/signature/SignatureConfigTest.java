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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for SignatureConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs
 * first, as it tests execution of a static block within SignatureConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignatureConfigTest {

  // This test must run first.
  @Test
  public void aaaTestInitialization() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Registry.getCatalogue("tinkpublickeysign"));
    assertThat(e.toString()).contains("no catalogue found");
    assertThat(e.toString()).contains("SignatureConfig.registe");
    e =
        assertThrows(
            GeneralSecurityException.class, () -> Registry.getCatalogue("tinkpublickeyverify"));
    assertThat(e.toString()).contains("no catalogue found");
    assertThat(e.toString()).contains("SignatureConfig.registe");
    String typeUrl = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
    e = assertThrows(GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));
    assertThat(e.toString()).contains("No key manager found");

    // Initialize the config.
    SignatureConfig.register();

    // After registration the key manager should be present.
    Registry.getKeyManager(typeUrl, PublicKeySign.class);

    // Running init() manually again should succeed.
    SignatureConfig.register();
  }

  @Test
  public void testNoFipsRegister() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // Register signature key manager
    SignatureConfig.register();

    // Check if all key types are registered when not using FIPS mode.
    String[] keyTypeUrlsSign = {
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
    };

    for (String typeUrl : keyTypeUrlsSign) {
      Registry.getKeyManager(typeUrl, PublicKeySign.class);
    }

    String[] keyTypeUrlsVerify = {
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
    };

    for (String typeUrl : keyTypeUrlsVerify) {
      Registry.getKeyManager(typeUrl, PublicKeyVerify.class);
    }
  }

  @Test
  public void testFipsRegisterFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register AEAD key manager
    SignatureConfig.register();

    // Check if all FIPS-compliant key types are registered when using FIPS mode.
    String[] keyTypeUrlsSign = {
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
    };

    for (String typeUrl : keyTypeUrlsSign) {
      Registry.getKeyManager(typeUrl, PublicKeySign.class);
    }

    String[] keyTypeUrlsVerify = {
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
    };

    for (String typeUrl : keyTypeUrlsVerify) {
      Registry.getKeyManager(typeUrl, PublicKeyVerify.class);
    }
  }

  @Test
  public void testFipsRegisterNonFipsKeys() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    // Register signature key manager
    SignatureConfig.register();

    // List of algorithms which are not part of FIPS and should not be registered.
    String[] keyTypeUrls = {
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
    };

    for (String typeUrl : keyTypeUrls) {
      assertThrows(GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(typeUrl));
    }
  }
}

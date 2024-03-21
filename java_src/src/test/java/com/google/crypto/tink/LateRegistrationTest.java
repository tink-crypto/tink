// Copyright 2024 Google LLC
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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.jwt.JwtMac;
import com.google.crypto.tink.jwt.JwtMacConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LateRegistrationTest {

  // A keyset with one AEAD key, serialized in Tink's JSON format.
  private static final String JSON_AEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 42818733,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"GhCC74uJ+2f4qlpaHwR4ylNQ\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 42818733,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void serializeAndParseBeforeRegistering() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_AEAD_KEYSET, InsecureSecretKeyAccess.get());

    // serializing and parsing keysets should work without registration.
    byte[] binarySerializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedHandle =
        TinkProtoKeysetFormat.parseKeyset(binarySerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedHandle.equalsKeyset(handle)).isTrue();

    String jsonSerializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(jsonSerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedHandle.equalsKeyset(handle)).isTrue();

    // Creating a primitive without registration should fail.
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(RegistryConfiguration.get(), Aead.class));

    AeadConfig.register();

    // After registration, the KeysetHandle that was parsed before should work.
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    Aead aead = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    assertThat(aead.decrypt(aead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  // A keyset with one JWT MAC key, serialized in Tink's JSON format.
  private static final String JSON_JWT_MAC_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 1685620571,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.JwtHmacKey\","
          + "        \"value\": \"GiDmRwUiwKDsPHd+2mSHwlLfzvkgoV5meopVKp+GCbhHthAB\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1685620571,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void serializeAndParseJwtKeysetBeforeRegistering() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_JWT_MAC_KEYSET, InsecureSecretKeyAccess.get());

    // Serializing and parsing keysets should work without registration.
    byte[] binarySerializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedHandle =
        TinkProtoKeysetFormat.parseKeyset(binarySerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedHandle.equalsKeyset(handle)).isTrue();

    String jsonSerializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(jsonSerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedHandle.equalsKeyset(handle)).isTrue();

    // Creating a primitive without registration should fail.
    assertThrows(
        GeneralSecurityException.class,
        () -> handle.getPrimitive(RegistryConfiguration.get(), JwtMac.class));

    JwtMacConfig.register();

    // The KeysetHandle that was parsed before register was called still fails. Because the
    // JwtMacWrapper requires full primitives but we can't construct them from the legacy key in the
    // KeysetHandle.
    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> handle.getPrimitive(RegistryConfiguration.get(), JwtMac.class));
    assertThat(thrown).hasMessageThat().contains("registration_errors");

    // but this now works.
    KeysetHandle handle2 =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_JWT_MAC_KEYSET, InsecureSecretKeyAccess.get());
    Instant now = Clock.systemUTC().instant();
    JwtMac jwtMac = handle2.getPrimitive(RegistryConfiguration.get(), JwtMac.class);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtMac.computeMacAndEncode(rawJwt);

    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtMac.verifyMacAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
  }
}

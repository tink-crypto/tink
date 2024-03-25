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
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.signature.SignatureConfig;
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

  private static final String JSON_ECDSA_PRIVATE_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 775870498,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPrivateKey\","
          + "        \"value\": \"GiA/E6s6KksNXrEd9hLdStvhsmdsONgpSODH/rZsBbBDehJMIiApA+NmYiv"
          + "xRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n27xnj9KcoGllF9NIFfQrDEP99FNH+Cne4"
          + "SBhgCEAIIAw==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 775870498,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  private static final String JSON_ECDSA_PUBLIC_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 775870498,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.EcdsaPublicKey\","
          + "        \"value\": \"IiApA+NmYivxRfhMuvTKZAwqETmn+WagBP/reucEjEvXkRog1AJ5GBzf+n2"
          + "7xnj9KcoGllF9NIFfQrDEP99FNH+Cne4SBhgCEAIIAw==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 775870498,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Test
  public void serializeAndParseSignatureKeysetBeforeRegistering() throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_ECDSA_PRIVATE_KEYSET, InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_ECDSA_PUBLIC_KEYSET, InsecureSecretKeyAccess.get());

    // serializing and parsing keysets should work without registration.
    byte[] binarySerializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedHandle =
        TinkProtoKeysetFormat.parseKeyset(binarySerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedHandle.equalsKeyset(privateHandle)).isTrue();

    String jsonSerializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(jsonSerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedHandle.equalsKeyset(privateHandle)).isTrue();

    byte[] binarySerializedPublicKeyset =
        TinkProtoKeysetFormat.serializeKeyset(publicHandle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedPublicHandle =
        TinkProtoKeysetFormat.parseKeyset(
            binarySerializedPublicKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedPublicHandle.equalsKeyset(publicHandle)).isTrue();

    String jsonSerializedPublicKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(publicHandle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedPublicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            jsonSerializedPublicKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedPublicHandle.equalsKeyset(publicHandle)).isTrue();

    // Before registration, this should fail.
    assertThrows(
        GeneralSecurityException.class,
        () -> privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> publicHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class));
    assertThrows(GeneralSecurityException.class, privateHandle::getPublicKeysetHandle);

    SignatureConfig.register();

    // After registration, the KeysetHandle that was parsed before should work.
    PublicKeySign signer =
        privateHandle.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
    PublicKeyVerify verifier =
        publicHandle.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
    PublicKeyVerify verifierFromPrivateKey =
        privateHandle
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);
    verifierFromPrivateKey.verify(sig, data);
  }

  // A keyset with one JWT public key sign keyset, serialized in Tink's JSON format.
  private static final String JSON_JWT_PUBLIC_KEY_SIGN_KEYSET =
      "{\"primaryKeyId\": 1742360595, \"key\": [{\"keyData\": {\"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey\", \"value\":"
          + "\"GiBgVYdAPg3Fa2FVFymGDYrI1trHMzVjhVNEMpIxG7t0HRJGIiBeoDMF9LS5BDCh6Ygq"
          + "E3DjHwWwnEKEI3WpPf8izEx1rRogbjQTXrTcw/1HKiiZm2Hqv41w7Vd44M9koyY/+VsP+SAQAQ==\","
          + "\"keyMaterialType\": \"ASYMMETRIC_PRIVATE\"}, \"status\": \"ENABLED\", \"keyId\":"
          + "1742360595, \"outputPrefixType\": \"TINK\"    }  ]}";

  // A keyset with one JWT public key verify keyset, serialized in Tink's JSON format.
  private static final String JSON_JWT_PUBLIC_KEY_VERIFY_KEYSET =
      "{\"primaryKeyId\": 1742360595, \"key\": [{ \"keyData\": {\"typeUrl\":"
          + "\"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\", \"value\":"
          + "\"EAEaIG40E1603MP9RyoomZth6r+NcO1XeODPZKMmP/lbD/kgIiBeoDMF9LS5BDCh6Ygq"
          + "E3DjHwWwnEKEI3WpPf8izEx1rQ==\","
          + "\"keyMaterialType\": \"ASYMMETRIC_PUBLIC\"}, \"status\": \"ENABLED\", \"keyId\":"
          + "1742360595, \"outputPrefixType\": \"TINK\"}]}";

  @Test
  public void readKeysetSignVerifyJwt_success() throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_SIGN_KEYSET, InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_VERIFY_KEYSET, InsecureSecretKeyAccess.get());

    // serializing and parsing keysets should work without registration.
    byte[] binarySerializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedHandle =
        TinkProtoKeysetFormat.parseKeyset(binarySerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedHandle.equalsKeyset(privateHandle)).isTrue();

    String jsonSerializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(privateHandle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(jsonSerializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedHandle.equalsKeyset(privateHandle)).isTrue();

    byte[] binarySerializedPublicKeyset =
        TinkProtoKeysetFormat.serializeKeyset(publicHandle, InsecureSecretKeyAccess.get());
    KeysetHandle binaryParsedPublicHandle =
        TinkProtoKeysetFormat.parseKeyset(
            binarySerializedPublicKeyset, InsecureSecretKeyAccess.get());
    assertThat(binaryParsedPublicHandle.equalsKeyset(publicHandle)).isTrue();

    String jsonSerializedPublicKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(publicHandle, InsecureSecretKeyAccess.get());
    KeysetHandle jsonParsedPublicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            jsonSerializedPublicKeyset, InsecureSecretKeyAccess.get());
    assertThat(jsonParsedPublicHandle.equalsKeyset(publicHandle)).isTrue();

    // Before registration, this should fail.
    assertThrows(
        GeneralSecurityException.class,
        () -> privateHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class));
    assertThrows(GeneralSecurityException.class, privateHandle::getPublicKeysetHandle);

    JwtSignatureConfig.register();

    // Calling getPrimitive on KeysetHandles parsed before register was called still fails.
    // Because JWT wrappers requires full primitives but we can't construct them from legacy key.
    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> privateHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class));
    assertThat(thrown).hasMessageThat().contains("registration_errors");
    GeneralSecurityException thrown2 =
        assertThrows(
            GeneralSecurityException.class,
            () -> publicHandle.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class));
    assertThat(thrown2).hasMessageThat().contains("registration_errors");

    // But parsing and then calling getPrimitive works.
    KeysetHandle privateHandle2 =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_SIGN_KEYSET, InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle2 =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_VERIFY_KEYSET, InsecureSecretKeyAccess.get());
    JwtPublicKeySign jwtPublicKeySign =
        privateHandle2.getPrimitive(RegistryConfiguration.get(), JwtPublicKeySign.class);
    JwtPublicKeyVerify jwtVerifier =
        publicHandle2.getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);
    JwtPublicKeyVerify jwtVerifierFromPrivateKey =
        privateHandle2
            .getPublicKeysetHandle()
            .getPrimitive(RegistryConfiguration.get(), JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant();
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtPublicKeySign.signAndEncode(rawJwt);
    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtVerifier.verifyAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
    VerifiedJwt verifiedJwt2 = jwtVerifierFromPrivateKey.verifyAndDecode(token, validator);
    assertThat(verifiedJwt2.getSubject()).isEqualTo("subject");
  }
}

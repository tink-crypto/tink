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

package com.google.crypto.tink.hybrid;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for EciesAeadHkdfPublicKeyManager. */
@RunWith(JUnit4.class)
public class EciesAeadHkdfPublicKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(HybridConfig.TINK_1_0_0);
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    EciesAeadHkdfPublicKeyManager keyManager = new EciesAeadHkdfPublicKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM.getValue();
    formats[1] = HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256.getValue();
    formats[2] = HybridKeyTemplates.createEciesAeadHkdfKeyTemplate(
              EllipticCurveType.NIST_P384, HashType.SHA512, EcPointFormat.COMPRESSED,
              AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
              "some HKDF salt".getBytes(Util.UTF_8)).getValue();
    formats[3] = HybridKeyTemplates.createEciesAeadHkdfKeyTemplate(
              EllipticCurveType.NIST_P521, HashType.SHA256, EcPointFormat.COMPRESSED,
              AeadKeyTemplates.AES256_GCM, "another HKDF salt".getBytes(Util.UTF_8)).getValue();

    EciesAeadHkdfPublicKey[] keys = new EciesAeadHkdfPublicKey[keyCount];
    EciesAeadHkdfPrivateKeyManager privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = ((EciesAeadHkdfPrivateKey) privateKeyManager.newKey(formats[i])).getPublicKey();
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (EciesAeadHkdfPublicKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        EciesAeadHkdfPublicKey keyFromJson = (EciesAeadHkdfPublicKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        EciesAeadHkdfKeyFormat formatFromJson =
            (EciesAeadHkdfKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(
            EciesAeadHkdfKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format: " + format.toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    EciesAeadHkdfPublicKeyManager keyManager = new EciesAeadHkdfPublicKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      EciesAeadHkdfPublicKey key = (EciesAeadHkdfPublicKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      EciesAeadHkdfKeyFormat format = (EciesAeadHkdfKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0, \"params\": {}, \"x\": \"xvalue\"}".getBytes(Util.UTF_8);
      EciesAeadHkdfPublicKey key = (EciesAeadHkdfPublicKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{}".getBytes(Util.UTF_8);
      EciesAeadHkdfKeyFormat format = (EciesAeadHkdfKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {}, "
          + "\"x\": \"xvalue\", \"y\": \"yvalue\", \"extraName\": 42}").getBytes(Util.UTF_8);
      EciesAeadHkdfPublicKey key = (EciesAeadHkdfPublicKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {}, \"extraName\": 42}").getBytes(Util.UTF_8);
      EciesAeadHkdfKeyFormat format = (EciesAeadHkdfKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": { \"kemParams\": {}}, "
          + "\"x\": \"xvalue\", \"y\": \"yvalue\"}").getBytes(Util.UTF_8);
      EciesAeadHkdfPublicKey key = (EciesAeadHkdfPublicKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete EciesAeadHkdfPublicKey.
      EciesAeadHkdfPublicKey key = EciesAeadHkdfPublicKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete EciesAeadHkdfPublicKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete EciesAeadHkdfKeyFormat.
      EciesAeadHkdfKeyFormat format = EciesAeadHkdfKeyFormat.newBuilder().build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete EciesAeadHkdfKeyFormat, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // Wrong serialized key proto.
      KeyData key = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Wrong key proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized EciesAeadHkdfPublicKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized EciesAeadHkdfKeyFormat");
    }
  }
}

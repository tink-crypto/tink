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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.subtle.MacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HmacKeyManager}. */
@RunWith(JUnit4.class)
public class HmacKeyManagerTest {
  @Test
  public void validateKeyFormat_empty() throws Exception {
    try {
      new HmacKeyManager().keyFactory().validateKeyFormat(HmacKeyFormat.getDefaultInstance());
      fail("At least the hash type needs to be set");
    } catch (GeneralSecurityException e) {
      // expected.
    }
  }

  private static HmacKeyFormat makeHmacKeyFormat(int keySize, int tagSize, HashType hashType) {
    HmacParams params = HmacParams.newBuilder()
        .setHash(hashType)
        .setTagSize(tagSize)
        .build();
    return HmacKeyFormat.newBuilder()
        .setParams(params)
        .setKeySize(keySize)
        .build();
  }

  @Test
  public void validateKeyFormat_tagSizesSha1() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 13, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 14, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 15, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 16, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 17, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 18, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 19, HashType.SHA1));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 20, HashType.SHA1));
    try {
      manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 21, HashType.SHA1));
      fail("SHA1 HMAC should not support tag size 21");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_tagSizesSha256() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA256));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA256));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA256));

    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 30, HashType.SHA256));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 31, HashType.SHA256));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 32, HashType.SHA256));
    try {
      manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 33, HashType.SHA256));
      fail("SHA256 HMAC should not support tag size 33");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_tagSizesSha512() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA512));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 11, HashType.SHA512));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 12, HashType.SHA512));

    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 62, HashType.SHA512));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 63, HashType.SHA512));
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 64, HashType.SHA512));
    try {
      manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 65, HashType.SHA512));
      fail("SHA256 HMAC should not support tag size 65");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_keySizes() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(16, 10, HashType.SHA256));
    try {
      manager.keyFactory().validateKeyFormat(makeHmacKeyFormat(15, 10, HashType.SHA256));
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_valid() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 10, HashType.SHA1)));
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 20, HashType.SHA1)));
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 10, HashType.SHA256)));
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 32, HashType.SHA256)));
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 10, HashType.SHA512)));
    manager.validateKey(manager.keyFactory().createKey(makeHmacKeyFormat(16, 64, HashType.SHA512)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    HmacKeyFormat keyFormat = makeHmacKeyFormat(16, 10, HashType.SHA256);
    HmacKey key = new HmacKeyManager().keyFactory().createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getParams().getTagSize()).isEqualTo(keyFormat.getParams().getTagSize());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKeyFormat keyFormat = makeHmacKeyFormat(16, 10, HashType.SHA256);
    int numKeys = 100;
    Set<String> keys = new TreeSet<String>();
    for (int i = 0; i < numKeys; ++i) {
      keys.add(
          TestUtil.hexEncode(
              manager.keyFactory().createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKey validKey = manager.keyFactory().createKey(makeHmacKeyFormat(16, 10, HashType.SHA1));
    try {
      manager.validateKey(HmacKey.newBuilder(validKey).setVersion(1).build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKey validKey = manager.keyFactory().createKey(makeHmacKeyFormat(16, 10, HashType.SHA1));
    try {
      manager.validateKey(
          HmacKey.newBuilder(validKey)
              .setKeyValue(ByteString.copyFrom(Random.randBytes(15)))
              .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
    try {
      manager
          .validateKey(
              HmacKey.newBuilder(validKey)
                  .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(0).build())
                  .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
    try {
      manager
          .validateKey(
              HmacKey.newBuilder(validKey)
                  .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(9).build())
                  .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
    try {
      manager
          .validateKey(
              HmacKey.newBuilder(validKey)
                  .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(21).build())
                  .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
    try {
      manager
          .validateKey(
              HmacKey.newBuilder(validKey)
                  .setParams(HmacParams.newBuilder(validKey.getParams()).setTagSize(32).build())
                  .build());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }


  @Test
  public void getPrimitive_worksForSha1() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKey validKey = manager.keyFactory().createKey(makeHmacKeyFormat(16, 19, HashType.SHA1));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new MacJce(
            "HMACSHA1", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"), 19);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void getPrimitive_worksForSha256() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKey validKey = manager.keyFactory().createKey(makeHmacKeyFormat(16, 29, HashType.SHA256));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new MacJce(
            "HMACSHA256", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"), 29);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }

  @Test
  public void getPrimitive_worksForSha512() throws Exception {
    HmacKeyManager manager = new HmacKeyManager();
    HmacKey validKey = manager.keyFactory().createKey(makeHmacKeyFormat(16, 33, HashType.SHA512));
    Mac managerMac = manager.getPrimitive(validKey, Mac.class);
    Mac directMac =
        new MacJce(
            "HMACSHA512", new SecretKeySpec(validKey.getKeyValue().toByteArray(), "HMAC"), 33);
    byte[] message = Random.randBytes(50);
    managerMac.verifyMac(directMac.computeMac(message), message);
  }
}

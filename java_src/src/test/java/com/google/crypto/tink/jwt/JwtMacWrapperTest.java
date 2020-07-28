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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtMacWrapper. */
@RunWith(JUnit4.class)
public class JwtMacWrapperTest {
  private final JwtMacWrapper wrapper = new JwtMacWrapper();

  @Test
  public void test_wrapEmpty_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapNoPrimary_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    primitiveSet.addPrimitive(
        new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapNoRaw_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    primitiveSet.addPrimitive(
        new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build());
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapSingle_works() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);
    JwtMac wrapped = wrapper.wrap(primitiveSet);

    ToBeSignedJwt tbs = new ToBeSignedJwt.Builder().setJwtId("blah").build();
    String compact = wrapped.createCompact(tbs);
    JwtValidator validator = new JwtValidator.Builder().build();
    Jwt token = wrapped.verifyCompact(compact, validator);

    assertThat(token.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapMultiple_works() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    JwtMac mac1 = new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC"));
    primitiveSet.addPrimitive(
        mac1,
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    JwtMac mac2 = new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC"));
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            mac2,
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitiveSet.setPrimary(entry);
    JwtMac wrapped = wrapper.wrap(primitiveSet);

    ToBeSignedJwt tbs = new ToBeSignedJwt.Builder().setJwtId("blah").build();
    String compact = wrapped.createCompact(tbs);
    JwtValidator validator = new JwtValidator.Builder().build();
    Jwt token = wrapped.verifyCompact(compact, validator);
    Jwt token2 = mac2.verifyCompact(compact, validator);

    assertThrows(GeneralSecurityException.class, () -> mac1.verifyCompact(compact, validator));
    assertThat(token.getJwtId()).isEqualTo("blah");
    assertThat(token.getAlgorithm()).isEqualTo("HS256");
    assertThat(token2.getJwtId()).isEqualTo("blah");
    assertThat(token2.getAlgorithm()).isEqualTo("HS256");
  }
}

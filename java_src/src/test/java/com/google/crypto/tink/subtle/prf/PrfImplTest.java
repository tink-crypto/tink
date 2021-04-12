// Copyright 2020 Google LLC
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
package com.google.crypto.tink.subtle.prf;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Enums.HashType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for HkdfPrf. Note that these tests rely on the tests for HkdfStreamingPrfTest to vet the
 * cryptographic gaurantees of Tink's PRF implementation. This class only tests the differences with
 * Prf.
 */
@RunWith(JUnit4.class)
public class PrfImplTest {

  @Test
  public void testComputePrf_returnsExpectedSize() throws Exception {
    PrfImpl prf =
        PrfImpl.wrap(
            new HkdfStreamingPrf(
                HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8)));

    byte[] out = prf.compute("input".getBytes(UTF_8), 12);

    assertThat(out).hasLength(12);
  }

  @Test
  public void testComputePrf_consistentPrefix() throws Exception {
    PrfImpl prf =
        PrfImpl.wrap(
            new HkdfStreamingPrf(
                HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8)));

    byte[] out = prf.compute("input".getBytes(UTF_8), 12);
    byte[] outLonger = prf.compute("input".getBytes(UTF_8), 16);
    byte[] outTruncated = Arrays.copyOf(outLonger, 12);

    assertThat(out).hasLength(12);
    assertArrayEquals(out, outTruncated);
  }

  @Test
  public void testComputePrf_identialToUnderlyingStreamingPrf() throws Exception {
    StreamingPrf streamer =
        new HkdfStreamingPrf(HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8));
    PrfImpl prf = PrfImpl.wrap(streamer);

    byte[] prfImplOut = prf.compute("input".getBytes(UTF_8), 12);
    byte[] prfStreamerOut = new byte[12];
    streamer.computePrf("input".getBytes(UTF_8)).read(prfStreamerOut);

    assertThat(prfImplOut).isEqualTo(prfStreamerOut);
  }

  @Test
  public void testComputePrf_incompleteStream() throws Exception {
    PrfImpl prf =
        PrfImpl.wrap(
            new StreamingPrf() {
              @Override
              public InputStream computePrf(byte[] input) {
                return new ByteArrayInputStream(new byte[] {1, 2, 3, 4, 5});
              }
            });

    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute("input".getBytes(UTF_8), 6);
          }
        });
  }

  @Test
  public void testComputePrf_enforcesParameterConstraints() throws Exception {
    PrfImpl prf =
        PrfImpl.wrap(
            new HkdfStreamingPrf(
                HashType.SHA1, "key0123456".getBytes(UTF_8), "salt".getBytes(UTF_8)));

    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute(null, 6);
          }
        });
    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute("input".getBytes(UTF_8), -1);
          }
        });
    assertThrows(
        GeneralSecurityException.class,
        new ThrowingRunnable() {
          @Override
          public void run() throws Throwable {
            prf.compute("input".getBytes(UTF_8), 0);
          }
        });
  }
}

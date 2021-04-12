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

import static java.lang.Math.min;

import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/** An implementation of the HKDF pseudorandom function, as given by RFC 5869. */
@Immutable
public class HkdfStreamingPrf implements StreamingPrf {
  private static String getJavaxHmacName(HashType hashType) throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return "HmacSha1";
      case SHA256:
        return "HmacSha256";
      case SHA384:
        return "HmacSha384";
      case SHA512:
        return "HmacSha512";
      default:
        throw new GeneralSecurityException(
            "No getJavaxHmacName for given hash " + hashType + " known");
    }
  }

  public HkdfStreamingPrf(final HashType hashType, final byte[] ikm, final byte[] salt) {
    this.hashType = hashType;
    this.ikm = Arrays.copyOf(ikm, ikm.length);
    this.salt = Arrays.copyOf(salt, salt.length);
  }

  private final HashType hashType;

  // Manual inspection shows that this is never mutated (and copied on construction)
  @SuppressWarnings("Immutable")
  private final byte[] ikm;

  // Manual inspection shows that this is never mutated (and copied on construction)
  @SuppressWarnings("Immutable")
  private final byte[] salt;

  private class HkdfInputStream extends InputStream {
    public HkdfInputStream(final byte[] input) {
      ctr = -1;
      this.input = Arrays.copyOf(input, input.length);
    }

    // We create the HMac lazily, so we don't have to throw an exception in computePrf.
    private void initialize() throws GeneralSecurityException, IOException {
      try {
        mac = EngineFactory.MAC.getInstance(getJavaxHmacName(hashType));
      } catch (GeneralSecurityException e) {
        throw new IOException("Creating HMac failed", e);
      }
      if (salt == null || salt.length == 0) {
        // According to RFC 5869, Section 2.2 the salt is optional. If no salt is provided
        // then HKDF uses a salt that is an array of zeros of the same length as the hash digest.
        mac.init(new SecretKeySpec(new byte[mac.getMacLength()], getJavaxHmacName(hashType)));
      } else {
        mac.init(new SecretKeySpec(salt, getJavaxHmacName(hashType)));
      }
      mac.update(ikm);
      prk = mac.doFinal();
      buffer = ByteBuffer.allocateDirect(0);
      buffer.mark();
      ctr = 0;
    }

    // Updates ti to ti+1 as in RFC 5869, section 2.3:
    // T(i+1) = HMAC-Hash(PRK, T(i) | info | 0x<i+1>)
    private void updateBuffer() throws GeneralSecurityException, IOException {
      mac.init(new SecretKeySpec(prk, getJavaxHmacName(hashType)));
      buffer.reset();
      mac.update(buffer);
      mac.update(input);
      ctr = ctr + 1;
      mac.update((byte) ctr);
      buffer = ByteBuffer.wrap(mac.doFinal());
      buffer.mark();
    }

    @Override
    public int read() throws IOException {
      byte[] oneByte = new byte[1];
      int ret = read(oneByte, 0, 1);
      if (ret == 1) {
        return oneByte[0] & 0xff;
      } else if (ret == -1) {
        return ret;
      } else {
        throw new IOException("Reading failed");
      }
    }

    @Override
    public int read(byte[] dst) throws IOException {
      return read(dst, 0, dst.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int totalRead = 0;
      try {
        if (ctr == -1) {
          initialize();
        }

        while (totalRead < len) {

          if (!buffer.hasRemaining()) {
            if (ctr == 255) {
              // End of stream.
              return totalRead;
            }
            updateBuffer();
          }

          int toRead = min(len - totalRead, buffer.remaining());
          buffer.get(b, off, toRead);
          off += toRead;
          totalRead += toRead;
        }
      } catch (GeneralSecurityException e) {
        mac = null;
        throw new IOException("HkdfInputStream failed", e);
      }
      return totalRead;
    }

    // The input to the PRF; called "info" in RFC 5869.
    private final byte[] input;

    private javax.crypto.Mac mac;
    // The pseudorandom key. By RFC 5869: PRK = HMAC-Hash(salt, IKM)
    private byte[] prk;
    // The last T(i) computed. By RFC 5869:
    //   T(0) = empty string
    //   T(i+1) = HMAC-Hash(PRK, T(i) | info | 0x<i+1>)
    private ByteBuffer buffer;
    // The current value of i which for which we store T(i) in buffer, or -1 if we are not
    // initialized.
    private int ctr;
  }

  @Override
  public InputStream computePrf(final byte[] input) {
    return new HkdfInputStream(input);
  }
}

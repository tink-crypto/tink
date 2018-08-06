// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) using PKCS1-v1_5 encoding) verifying
 * with JCE.
 */
public final class RsaSsaPkcs1VerifyJce implements PublicKeyVerify {
  private final RSAPublicKey publicKey;
  private final String signatureAlgorithm;

  public RsaSsaPkcs1VerifyJce(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {
    this.publicKey = pubKey;
    this.signatureAlgorithm = SubtleUtil.toRsaSsaPkcs1Algo(hash);
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    Signature verifier = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean verified = false;
    try {
      verified = verifier.verify(signature);
    } catch (java.lang.RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }
}

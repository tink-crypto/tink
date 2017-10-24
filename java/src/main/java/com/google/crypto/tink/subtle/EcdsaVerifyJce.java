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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.PublicKeyVerify;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/** Ecdsa signature's verification in JCE. */
public final class EcdsaVerifyJce implements PublicKeyVerify {
  private final ECPublicKey publicKey;
  private final String signatureAlgorithm;

  public EcdsaVerifyJce(final ECPublicKey pubKey, String signatureAlgorithm)
      throws GeneralSecurityException {
    EllipticCurves.checkPublicKey(pubKey);
    this.publicKey = pubKey;
    this.signatureAlgorithm = signatureAlgorithm;
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

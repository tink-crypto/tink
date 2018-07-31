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

import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;

/** Helper methods. */
public class SubtleUtil {

  /**
   * Returns the Ecdsa algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's Ecdsa algorithm name for the hash.
   * @throw GeneralSecurityExceptio if {@code hash} is not supported or is not safe for digital
   *     signature.
   */
  public static String toEcdsaAlgo(HashType hash) throws GeneralSecurityException {
    Validators.validateSignatureHash(hash);
    return hash + "withECDSA";
  }

  /**
   * Returns the RSA SSA (Signature with Appendix) PKCS1 algorithm name corresponding to a hash
   * type.
   *
   * @param hash the hash type
   * @return the JCE's RSA SSA PKCS1 algorithm name for the hash.
   * @throw GeneralSecurityException if {@code hash} is not supported or is not safe for digital
   *     signature.
   */
  public static String toRsaSsaPkcs1Algo(HashType hash) throws GeneralSecurityException {
    Validators.validateSignatureHash(hash);
    return hash + "withRSA";
  }

  /**
   * Best-effort checks that this is Android.
   *
   * @return true if running on Android.
   */
  public static boolean isAndroid() {
    try {
      Class.forName("android.app.Application", /*initialize=*/ false, null);
      return true;
    } catch (Exception e) {
      // If Application isn't loaded, it might as well not be Android.
      return false;
    }
  }
}

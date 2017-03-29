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

package com.google.cloud.crypto.tink.subtle;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/**
 * Interface and its implentations to make JCE Engines have a common parent. There's no expected
 * reason to directly import this for users of Tink, but it might be needed to implement it
 * (say, if someone wants a new type of engine).
 */
public interface EngineWrapper<T> {

  /**
   * Cipher wrapper.
   */
  class TCipher implements EngineWrapper<Cipher> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public Cipher getInstance(String algorithm, Provider provider) throws GeneralSecurityException {
      if (provider == null) {
        return Cipher.getInstance(algorithm);
      } else {
        return Cipher.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * Mac wrapper.
   */
  class TMac implements EngineWrapper<Mac> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public Mac getInstance(String algorithm, Provider provider) throws GeneralSecurityException {
      if (provider == null) {
        return Mac.getInstance(algorithm);
      } else {
        return Mac.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * KeyPairGenerator wrapper.
   */
  class TKeyPairGenerator implements EngineWrapper<KeyPairGenerator> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public KeyPairGenerator getInstance(String algorithm, Provider provider)
        throws GeneralSecurityException {
      if (provider == null) {
        return KeyPairGenerator.getInstance(algorithm);
      } else {
        return KeyPairGenerator.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * MessageDigest wrapper.
   */
  class TMessageDigest implements EngineWrapper<MessageDigest> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public MessageDigest getInstance(String algorithm, Provider provider)
        throws GeneralSecurityException {
      if (provider == null) {
        return MessageDigest.getInstance(algorithm);
      } else {
        return MessageDigest.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * Signature wrapper.
   */
  class TSignature implements EngineWrapper<Signature> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public Signature getInstance(String algorithm, Provider provider)
        throws GeneralSecurityException {
      if (provider == null) {
        return Signature.getInstance(algorithm);
      } else {
        return Signature.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * KeyFactory wrapper.
   */
  class TKeyFactory implements EngineWrapper<KeyFactory> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public KeyFactory getInstance(String algorithm, Provider provider)
        throws GeneralSecurityException {
      if (provider == null) {
        return KeyFactory.getInstance(algorithm);
      } else {
        return KeyFactory.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * KeyAgreement wrapper.
   */
  class TKeyAgreement implements EngineWrapper<KeyAgreement> {
    @SuppressWarnings("InsecureCryptoUsage")
    @Override
    public KeyAgreement getInstance(String algorithm, Provider provider)
        throws GeneralSecurityException {
      if (provider == null) {
        return KeyAgreement.getInstance(algorithm);
      } else {
        return KeyAgreement.getInstance(algorithm, provider);
      }
    }
  }

  /**
   * Should call T.getInstance(...).
   */
  public T getInstance(String algorithm, Provider provider) throws GeneralSecurityException;

}

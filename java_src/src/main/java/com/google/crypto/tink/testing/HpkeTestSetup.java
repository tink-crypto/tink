// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.subtle.Hex;
import javax.annotation.Nullable;

/** Helper class that contains setup parameter values for an individual test vector. */
public final class HpkeTestSetup {
  public final byte[] info; // info
  public final byte[] senderEphemeralPublicKey; // pkEm
  public final byte[] senderEphemeralPrivateKey; // skEm
  @Nullable public final byte[] senderPublicKey; // pkSm
  @Nullable public final byte[] senderPrivateKey; // skSm
  public final byte[] recipientPublicKey; // pkRm
  public final byte[] recipientPrivateKey; // skRm
  public final byte[] encapsulatedKey; // enc
  public final byte[] sharedSecret; // shared_secret
  public final byte[] keyScheduleContext; // key_schedule_context
  public final byte[] secret; // secret
  public final byte[] key; // key
  public final byte[] baseNonce; // base_nonce

  /** Builder class for {@link HpkeTestSetup}. */
  public static final class Builder {
    private String info; // info
    private String senderEphemeralPublicKey; // pkEm
    private String senderEphemeralPrivateKey; // skEm
    private String senderPublicKey; // pkSm
    private String senderPrivateKey; // skSm
    private String recipientPublicKey; // pkRm
    private String recipientPrivateKey; // skRm
    private String encapsulatedKey; // enc
    private String sharedSecret; // shared_secret
    private String keyScheduleContext; // key_schedule_context
    private String secret; // secret
    private String key; // key
    private String baseNonce; // base_nonce

    private Builder() {}

    public Builder setInfo(String info) {
      this.info = info;
      return this;
    }

    public Builder setSenderPublicKey(String senderPublicKey) {
      this.senderPublicKey = senderPublicKey;
      return this;
    }

    public Builder setSenderPrivateKey(String senderPrivateKey) {
      this.senderPrivateKey = senderPrivateKey;
      return this;
    }

    public Builder setSenderEphemeralPublicKey(String senderEphemeralPublicKey) {
      this.senderEphemeralPublicKey = senderEphemeralPublicKey;
      return this;
    }

    public Builder setSenderEphemeralPrivateKey(String senderEphemeralPrivateKey) {
      this.senderEphemeralPrivateKey = senderEphemeralPrivateKey;
      return this;
    }

    public Builder setRecipientPublicKey(String recipientPublicKey) {
      this.recipientPublicKey = recipientPublicKey;
      return this;
    }

    public Builder setRecipientPrivateKey(String recipientPrivateKey) {
      this.recipientPrivateKey = recipientPrivateKey;
      return this;
    }

    public Builder setEncapsulatedKey(String encapsulatedKey) {
      this.encapsulatedKey = encapsulatedKey;
      return this;
    }

    public Builder setSharedSecret(String sharedSecret) {
      this.sharedSecret = sharedSecret;
      return this;
    }

    public Builder setKeyScheduleContext(String keyScheduleContext) {
      this.keyScheduleContext = keyScheduleContext;
      return this;
    }

    public Builder setSecret(String secret) {
      this.secret = secret;
      return this;
    }

    public Builder setKey(String key) {
      this.key = key;
      return this;
    }

    public Builder setBaseNonce(String baseNonce) {
      this.baseNonce = baseNonce;
      return this;
    }

    public HpkeTestSetup build() {
      if (info == null) {
        throw new IllegalArgumentException("Info must be non-null.");
      }
      if (senderEphemeralPublicKey == null) {
        throw new IllegalArgumentException("Sender ephemeral public key must be non-null.");
      }
      if (senderEphemeralPrivateKey == null) {
        throw new IllegalArgumentException("Sender ephemeral private key must be non-null.");
      }
      if (recipientPublicKey == null) {
        throw new IllegalArgumentException("Recipient public key must be non-null.");
      }
      if (recipientPrivateKey == null) {
        throw new IllegalArgumentException("Recipient private key must be non-null.");
      }
      if (encapsulatedKey == null) {
        throw new IllegalArgumentException("Encapsulated key must be non-null.");
      }
      if (sharedSecret == null) {
        throw new IllegalArgumentException("Shared secret must be non-null.");
      }
      if (keyScheduleContext == null) {
        throw new IllegalArgumentException("Key schedule context must be non-null.");
      }
      if (secret == null) {
        throw new IllegalArgumentException("Secret must be non-null.");
      }
      if (key == null) {
        throw new IllegalArgumentException("Key must be non-null.");
      }
      if (baseNonce == null) {
        throw new IllegalArgumentException("Base nonce must be non-null.");
      }

      return new HpkeTestSetup(
          info,
          senderEphemeralPublicKey,
          senderEphemeralPrivateKey,
          senderPublicKey,
          senderPrivateKey,
          recipientPublicKey,
          recipientPrivateKey,
          encapsulatedKey,
          sharedSecret,
          keyScheduleContext,
          secret,
          key,
          baseNonce);
    }
  }

  private HpkeTestSetup(
      String info,
      String senderEphemeralPublicKey,
      String senderEphemeralPrivateKey,
      String senderPublicKey,
      String senderPrivateKey,
      String recipientPublicKey,
      String recipientPrivateKey,
      String encapsulatedKey,
      String sharedSecret,
      String keyScheduleContext,
      String secret,
      String key,
      String baseNonce) {
    this.info = Hex.decode(info);
    this.senderEphemeralPublicKey = Hex.decode(senderEphemeralPublicKey);
    this.senderEphemeralPrivateKey = Hex.decode(senderEphemeralPrivateKey);
    // senderPublicKey is optional and might not be set.
    if (senderPublicKey != null) {
      this.senderPublicKey = Hex.decode(senderPublicKey);
    } else {
      this.senderPublicKey = null;
    }
    // senderPrivateKey is optional and might not be set.
    if (senderPrivateKey != null) {
      this.senderPrivateKey = Hex.decode(senderPrivateKey);
    } else {
      this.senderPrivateKey = null;
    }
    this.recipientPublicKey = Hex.decode(recipientPublicKey);
    this.recipientPrivateKey = Hex.decode(recipientPrivateKey);
    this.encapsulatedKey = Hex.decode(encapsulatedKey);
    this.sharedSecret = Hex.decode(sharedSecret);
    this.keyScheduleContext = Hex.decode(keyScheduleContext);
    this.secret = Hex.decode(secret);
    this.key = Hex.decode(key);
    this.baseNonce = Hex.decode(baseNonce);
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public String toString() {
    String s = "";
    s += "info: " + Hex.encode(info) + "\n";
    s += "pkEm: " + Hex.encode(senderPublicKey) + "\n";
    s += "skEm: " + Hex.encode(senderPrivateKey) + "\n";
    if (senderPublicKey != null) {
      s += "pkSm: " + Hex.encode(senderPublicKey) + "\n";
    }
    if (senderPrivateKey != null) {
      s += "skSm: " + Hex.encode(senderPrivateKey) + "\n";
    }
    s += "pkRm: " + Hex.encode(recipientPublicKey) + "\n";
    s += "skRm: " + Hex.encode(recipientPrivateKey) + "\n";
    s += "enc: " + Hex.encode(encapsulatedKey) + "\n";
    s += "shared_secret: " + Hex.encode(sharedSecret) + "\n";
    s += "key_schedule_context: " + Hex.encode(keyScheduleContext) + "\n";
    s += "secret: " + Hex.encode(secret) + "\n";
    s += "key: " + Hex.encode(key) + "\n";
    s += "base_nonce: " + Hex.encode(baseNonce);
    return s;
  }
}

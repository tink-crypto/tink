// Copyright 2023 Google LLC
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

package com.google.tinkuser;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.daead.DeterministicAeadKeyTemplates;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Example user code */
public final class TinkUser {
  public Aead useReadNoSecret(byte[] b) throws GeneralSecurityException {
    return KeysetHandle.readNoSecret(b).getPrimitive(Aead.class);
  }
  public Aead useBinaryReader(byte[] b) throws GeneralSecurityException, IOException {
    return KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(b)).getPrimitive(Aead.class);
  }
  public Aead useAnyReader(KeysetReader r) throws GeneralSecurityException, IOException {
    return KeysetHandle.readNoSecret(r).getPrimitive(Aead.class);
  }

  public void macKeyTemplateUser() throws Exception {
    Object a = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    Object b = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_256BITTAG);
    Object c = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_256BITTAG);
    Object d = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA512_512BITTAG);
    Object e = KeysetHandle.generateNew(MacKeyTemplates.AES_CMAC);
  }

  public void aeadKeyTemplateUser() throws Exception {
    Object a = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
    Object b = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
    Object c = KeysetHandle.generateNew(AeadKeyTemplates.AES128_EAX);
    Object d = KeysetHandle.generateNew(AeadKeyTemplates.AES256_EAX);
    Object e = KeysetHandle.generateNew(AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    Object f = KeysetHandle.generateNew(AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
    Object g = KeysetHandle.generateNew(AeadKeyTemplates.CHACHA20_POLY1305);
    Object h = KeysetHandle.generateNew(AeadKeyTemplates.XCHACHA20_POLY1305);
  }

  public void deterministicAeadKeyTemplateUser() throws Exception {
    Object a = KeysetHandle.generateNew(DeterministicAeadKeyTemplates.AES256_SIV);
  }

  public void streamingAeadKeyTemplateUser() throws Exception {
    Object a = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB);
    Object b = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_1MB);
    Object c = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB);
    Object d = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_1MB);
    Object e = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB);
    Object f = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_1MB);
    Object g = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);
    Object h = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_1MB);
  }
}

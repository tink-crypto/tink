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

package com.google.crypto.tink;

import java.security.GeneralSecurityException;

/** A KmsClient knows how to produce primitives backed by keys stored in remote KMS services. */
public interface KmsClient {
  /** @return true if this client does support {@code keyUri} */
  public boolean doesSupport(String keyUri);

  /**
   * Loads the credentials in {@code credentialPath}. If {@code credentialPath} is null, loads the
   * default credentials.
   */
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException;

  /** Loads the default credentials. */
  public KmsClient withDefaultCredentials() throws GeneralSecurityException;

  /**
   * Gets an {@code Aead} backed by {@code keyUri}.
   *
   * @throws GeneralSecurityException if the URI is not supported or invalid
   */
  public Aead getAead(String keyUri) throws GeneralSecurityException;
}

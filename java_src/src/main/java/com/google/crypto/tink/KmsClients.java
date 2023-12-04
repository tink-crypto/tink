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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A container for {@link KmsClient}-objects that are needed by {@link KeyManager}-objects for
 * primitives that use KMS-managed keys.
 *
 * <p>This class consists exclusively of static methods that register and load {@link
 * KmsClient}-objects.
 *
 * @deprecated Registering KmsClient is discouraged. Instead call {@link KmsClient#getAead} to get a
 *     remote {@link Aead}. Use this {@link Aead} to encrypt a keyset with {@link
 *     TinkProtoKeysetFormat#serializeEncryptedKeyset}, or to create an envelope {@link Aead} using
 *     {@link com.google.crypto.tink.aead.KmsEnvelopeAead#create}.
 * @since 1.0.0
 */
@Deprecated // We do not recommend using this API, but there are no plans to remove it.
public final class KmsClients {
  // The list of KmsClients loaded automatically using ServiceLoader.
  private static List<KmsClient> autoClients;

  private static final CopyOnWriteArrayList<KmsClient> clients = new CopyOnWriteArrayList<>();

  /**
   * Adds a client to the list of known {@link KmsClient}-objects.
   *
   * <p>This function will always add the {@code client} to a global list. So this function should
   * only be called on startup and not on every operation. Otherwise this list may keep growing.
   *
   * @deprecated Registering KmsClient is discouraged. Instead call {@link KmsClient#getAead} to get
   *     a remote {@link Aead}. Use this {@link Aead} to encrypt a keyset with {@link
   *     TinkProtoKeysetFormat#serializeEncryptedKeyset}, or to create an envelope {@link Aead}
   *     using {@link com.google.crypto.tink.aead.KmsEnvelopeAead#create}.
   */
  @Deprecated // We do not recommend using this API, but there are no plans to remove it.
  public static void add(KmsClient client) {
    clients.add(client);
  }

  /**
   * Returns the first {@link KmsClient} registered with {@link KmsClients#add} that supports {@code
   * keyUri}.
   *
   * @deprecated Instead, keep your own instance or list of {@link KmsClient}.
   * @throws GeneralSecurityException if cannot found any KMS clients that support {@code keyUri}
   */
  @Deprecated // We do not recommend using this API, but there are no plans to remove it.
  public static KmsClient get(String keyUri) throws GeneralSecurityException {
    for (KmsClient client : clients) {
      if (client.doesSupport(keyUri)) {
        return client;
      }
    }
    throw new GeneralSecurityException("No KMS client does support: " + keyUri);
  }

  /**
   * Returns the first {@link KmsClient} automatically loaded with {@link java.util.ServiceLoader}
   * that supports {@code keyUri}.
   *
   * <p><b>Warning</b> This method searches over the classpath for all implementations of {@link
   * KmsClient}. An attacker that can insert a class in your classpath (e.g., someone controlling a
   * library that you're using) could provide a fake {@link KmsClient} that steal your keys. For
   * this reason Tink does not use this method.
   *
   * @deprecated Don't use this.
   * @throws GeneralSecurityException if cannot found any KMS clients that support {@code keyUri}
   */
  @Deprecated
  public static synchronized KmsClient getAutoLoaded(String keyUri)
      throws GeneralSecurityException {
    if (autoClients == null) {
      autoClients = loadAutoKmsClients();
    }
    for (KmsClient client : autoClients) {
      if (client.doesSupport(keyUri)) {
        return client;
      }
    }
    throw new GeneralSecurityException("No KMS client does support: " + keyUri);
  }

  static void reset() {
    clients.clear();
  }

  private static List<KmsClient> loadAutoKmsClients() {
    List<KmsClient> clients = new ArrayList<>();
    ServiceLoader<KmsClient> clientLoader = ServiceLoader.load(KmsClient.class);
    for (KmsClient element : clientLoader) {
      clients.add(element);
    }
    return Collections.unmodifiableList(clients);
  }

  private KmsClients() {}
}

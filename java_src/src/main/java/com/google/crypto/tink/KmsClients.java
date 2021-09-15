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
import java.util.Iterator;
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
 * @since 1.0.0
 */
public final class KmsClients {
  // The list of KmsClients loaded automatically using ServiceLoader.
  private static List<KmsClient> autoClients;

  private static final CopyOnWriteArrayList<KmsClient> clients =
      new CopyOnWriteArrayList<KmsClient>();

  /** Adds a client to the list of known {@link KmsClient}-objects. */
  public static void add(KmsClient client) {
    clients.add(client);
  }

  /**
   * Returns the first {@link KmsClient} registered with {@link KmsClients#add} that supports {@code
   * keyUri}.
   *
   * @throws GeneralSecurityException if cannot found any KMS clients that support {@code keyUri}
   */
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
   * this reason Tink does not use this method. It is used by <a
   * href="https://github.com/google/tink/tree/master/tools/tinkey">Tinkey</a> which needs to talk
   * to custom, in-house key management systems.
   *
   * @throws GeneralSecurityException if cannot found any KMS clients that support {@code keyUri}
   */
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
    List<KmsClient> clients = new ArrayList<KmsClient>();
    ServiceLoader<KmsClient> clientLoader = ServiceLoader.load(KmsClient.class);
    Iterator<KmsClient> i = clientLoader.iterator();
    while (i.hasNext()) {
      clients.add(i.next());
    }
    return Collections.unmodifiableList(clients);
  }

  private KmsClients() {}
}

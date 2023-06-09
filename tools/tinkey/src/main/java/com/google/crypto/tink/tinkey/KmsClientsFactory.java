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

package com.google.crypto.tink.tinkey;

import com.google.crypto.tink.KmsClient;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Allows creating {@link KmsClient} objects.
 *
 * <p>Tink {@link KmsClient} which are registered have the really unfortunate property that they are
 * modifiable. For Tinkey this should never be a problem, since one always uses the client only
 * once. However, for testing Tinkey it is a problem. Hence, we avoid the class and simply use this
 * one here instead.
 */
final class KmsClientsFactory {

  private List<Supplier<KmsClient>> factories = new ArrayList<>();

  /** Create a new KmsClientsFactory without any registered factory. */
  public KmsClientsFactory() {}

  private static final KmsClientsFactory globalInstance = new KmsClientsFactory();

  /** A unique global instance. */
  public static KmsClientsFactory globalInstance() {
    return globalInstance;
  }

  /**
   * Enumerates all registered factories, creates a new client for each, and returns one if it
   * supports keyUri.
   */
  public KmsClient newClientFor(String keyUri) throws GeneralSecurityException {
    for (Supplier<KmsClient> factory : factories) {
      KmsClient client = factory.get();
      if (client.doesSupport(keyUri)) {
        return client;
      }
    }
    throw new GeneralSecurityException("Unable to find factory for keyUri: " + keyUri);
  }

  /** Registers an additional factory. */
  public void addFactory(Supplier<KmsClient> factory) {
    factories.add(factory);
  }
}

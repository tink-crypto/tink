/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
// [START java-jwt-generate-public-jwk-set-example]
package jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwkSetConverter;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A command-line example for generating the public JWT keyset in JWK set format.
 *
 * <p>It loads cleartext private keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>private-keyset-file: Name of the input file containing the private keyset.
 *   <li>public-jwkset-file: Name of the output file containing the public key in JWK set format.
 */
public final class JwtGeneratePublicJwkSet {
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      System.err.printf("Expected 2 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java JwtGeneratePublicJwkSet private-keyset-file public-jwk-set-file");
      System.exit(1);
    }

    Path privateKeysetFile = Paths.get(args[0]);
    Path publicJwkSetFile = Paths.get(args[1]);

    // Register all JWT signature key types with the Tink runtime.
    JwtSignatureConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle privateKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(privateKeysetFile), UTF_8),
            InsecureSecretKeyAccess.get());

    // Export the public keyset as JWK set.
    String publicJwkSet =
        JwkSetConverter.fromPublicKeysetHandle(privateKeysetHandle.getPublicKeysetHandle());
    Files.write(publicJwkSetFile, publicJwkSet.getBytes(UTF_8));
  }

  private JwtGeneratePublicJwkSet() {}
}
// [END java-jwt-generate-public-jwk-set-example]

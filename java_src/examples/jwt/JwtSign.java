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
// [START java-jwt-sign-example]
package jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.RawJwt;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

/**
 * A command-line utility for signing JSON Web Tokens (JWTs).
 *
 * <p>It loads cleartext private keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>private-keyset-file: Name of the input file containing the private keyset.
 *   <li>audience: The audience claim to be used in the token
 *   <li>token-file: name of the output file containing the signed JWT.
 */
public final class JwtSign {
  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.err.printf("Expected 3 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java JwtSign private-keyset-file audience token-file");
      System.exit(1);
    }

    Path privateKeysetFile = Paths.get(args[0]);
    String audience = args[1];
    Path tokenFile = Paths.get(args[2]);

    // Register all JWT signature key types with the Tink runtime.
    JwtSignatureConfig.register();

    // Read the private keyset into a KeysetHandle.
    KeysetHandle privateKeysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(privateKeysetFile), UTF_8),
            InsecureSecretKeyAccess.get());

    // Get the primitive.
    JwtPublicKeySign signer = privateKeysetHandle.getPrimitive(JwtPublicKeySign.class);

    // Use the primitive to sign a token that expires in 100 seconds.
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .addAudience(audience)
            .setExpiration(Instant.now().plusSeconds(100))
            .build();
    String signedToken = signer.signAndEncode(rawJwt);
    Files.write(tokenFile, signedToken.getBytes(UTF_8));
  }

  private JwtSign() {}
}
// [END java-jwt-sign-example]

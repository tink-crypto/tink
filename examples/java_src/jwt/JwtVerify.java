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
// [START java-jwt-verify-example]
package jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwkSetConverter;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.tinkkey.KeyAccess;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * A command-line utility for verifying JSON Web Tokens (JWTs).
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>public-jwkset-file: Name of the input file containing the public keyset in JWK set format.
 *   <li>audience: The audience claim to be used in the token
 *   <li>token-file: name of the input file containing the signed JWT.
 */
public final class JwtVerify {
  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.err.printf("Expected 3 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java JwtVerify public-jwk-set-file audience token-file");
      System.exit(1);
    }

    File publicJwkSetFile = new File(args[0]);
    String audience = args[1];
    File tokenFile = new File(args[2]);

    // Register all JWT signature key types with the Tink runtime.
    JwtSignatureConfig.register();

    // Read the public keyset in JWK set format into a KeysetHandle.
    KeysetHandle publicKeysetHandle = null;
    try {
      String publicJwkSet = new String(Files.readAllBytes(publicJwkSetFile.toPath()), UTF_8);
      publicKeysetHandle = JwkSetConverter.toKeysetHandle(publicJwkSet, KeyAccess.publicAccess());
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Cannot read keyset, got error: " + ex);
      System.exit(1);
    }

    List<String> lines = Files.readAllLines(tokenFile.toPath());
    if (lines.size() != 1) {
      System.err.printf("The signature file should contain only one line,  got %d", lines.size());
      System.exit(1);
    }
    String signedToken = lines.get(0).trim();

    // Get the primitive.
    JwtPublicKeyVerify verifier = null;
    try {
      verifier = publicKeysetHandle.getPrimitive(JwtPublicKeyVerify.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to verify a token.
    try {
      JwtValidator validator = JwtValidator.newBuilder().expectAudience(audience).build();
      VerifiedJwt verifiedJwt = verifier.verifyAndDecode(signedToken, validator);
      long seconds = ChronoUnit.SECONDS.between(Instant.now(), verifiedJwt.getExpiration());
      System.out.println("Token is valid and expires in " + seconds + " seconds.");
    } catch (GeneralSecurityException ex) {
      System.err.println("JWT verification failed.");
      System.exit(1);
    }

    System.exit(0);
  }

  private JwtVerify() {}
}
// [END java-jwt-verify-example]

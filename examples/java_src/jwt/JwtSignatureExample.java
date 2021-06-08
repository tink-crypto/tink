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
// [START jwt-signature-example]
package jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * A command-line utility for signing and verifying JSON Web Tokens (JWTs).
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: either 'sign' or 'verify'.
 *   <li>key-file: Read the key material from this file.
 *   <li>subject: The subject claim to be used in the token
 *   <li>token-file: name of the file containing the signed JWT.
 */
public final class JwtSignatureExample {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.printf("Expected 4 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java JwtSignatureExample sign/verify key-file subject token-file");
      System.exit(1);
    }

    String mode = args[0];
    if (!mode.equals("sign") && !mode.equals("verify")) {
      System.err.println("Incorrect mode. Please select sign or verify.");
      System.exit(1);
    }
    File keyFile = new File(args[1]);
    String subject = args[2];
    File tokenFile = new File(args[3]);

    // Register all JWT signature key types with the Tink runtime.
    JwtSignatureConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle = null;
    try {
      handle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyFile));
    } catch (GeneralSecurityException | IOException ex) {
      System.err.println("Cannot read keyset, got error: " + ex);
      System.exit(1);
    }

    if (mode.equals("sign")) {
      // Get the primitive.
      JwtPublicKeySign signer = null;
      try {
        signer = handle.getPrimitive(JwtPublicKeySign.class);
      } catch (GeneralSecurityException ex) {
        System.err.println("Cannot create primitive, got error: " + ex);
        System.exit(1);
      }

      // Use the primitive to sign a token that expires in 100 seconds.
      RawJwt rawJwt = RawJwt.newBuilder()
          .setSubject(subject)
          .setExpiration(Instant.now().plusSeconds(100))
          .build();
      String signedToken = signer.signAndEncode(rawJwt);
      try (FileOutputStream stream = new FileOutputStream(tokenFile)) {
        stream.write(signedToken.getBytes(UTF_8));
      }
      System.exit(0);
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
      verifier = handle.getPrimitive(JwtPublicKeyVerify.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to verify a token.
    try {
      JwtValidator validator = JwtValidator.newBuilder().expectSubject(subject).build();
      VerifiedJwt verifiedJwt = verifier.verifyAndDecode(signedToken, validator);
      long seconds = ChronoUnit.SECONDS.between(Instant.now(), verifiedJwt.getExpiration());
      System.out.println("Token is valid and expires in " + seconds + " seconds.");
    } catch (GeneralSecurityException ex) {
      System.err.println("JWT verification failed.");
      System.exit(1);
    }

    System.exit(0);
  }

  private JwtSignatureExample() {}
}
// [END jwt-signature-example]

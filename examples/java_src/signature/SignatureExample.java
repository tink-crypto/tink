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
// [START digital-signature-example]
package signature;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Hex;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * A command-line utility for digitally signing and verifying a file.
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: either 'sign' or 'verify'.
 *   <li>key-file: Read the key material from this file.
 *   <li>input-file: Read the input from this file.
 *   <li>signature-file: name of the file containing a hexadecimal signature of the input file.
 */
public final class SignatureExample {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.printf("Expected 4 parameters, got %d\n", args.length);
      System.err.println(
          "Usage: java SignatureExample sign/verify key-file input-file signature-file");
      System.exit(1);
    }

    String mode = args[0];
    if (!mode.equals("sign") && !mode.equals("verify")) {
      System.err.println("Incorrect mode. Please select sign or verify.");
      System.exit(1);
    }
    File keyFile = new File(args[1]);
    byte[] msg = Files.readAllBytes(Paths.get(args[2]));
    File signatureFile = new File(args[3]);

    // Register all signature key types with the Tink runtime.
    SignatureConfig.register();

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
      PublicKeySign signer = null;
      try {
        signer = handle.getPrimitive(PublicKeySign.class);
      } catch (GeneralSecurityException ex) {
        System.err.println("Cannot create primitive, got error: " + ex);
        System.exit(1);
      }

      // Use the primitive to sign data.
      byte[] signature = signer.sign(msg);
      try (FileOutputStream stream = new FileOutputStream(signatureFile)) {
        stream.write(Hex.encode(signature).getBytes(UTF_8));
      }
      System.exit(0);
    }

    List<String> lines = Files.readAllLines(signatureFile.toPath());
    if (lines.size() != 1) {
      System.err.printf("The signature file should contain only one line,  got %d", lines.size());
      System.exit(1);
    }
    byte[] signature = Hex.decode(lines.get(0).trim());

    // Get the primitive.
    PublicKeyVerify verifier = null;
    try {
      verifier = handle.getPrimitive(PublicKeyVerify.class);
    } catch (GeneralSecurityException ex) {
      System.err.println("Cannot create primitive, got error: " + ex);
      System.exit(1);
    }

    // Use the primitive to verify data.
    try {
      verifier.verify(signature, msg);
    } catch (GeneralSecurityException ex) {
      System.err.println("Signature verification failed.");
      System.exit(1);
    }

    System.exit(0);
  }

  private SignatureExample() {}
}
// [END digital-signature-example]

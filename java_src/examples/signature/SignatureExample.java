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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.signature.SignatureConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
    Path keyFile = Paths.get(args[1]);
    byte[] msg = Files.readAllBytes(Paths.get(args[2]));
    Path signatureFile = Paths.get(args[3]);

    // Register all signature key types with the Tink runtime.
    SignatureConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(keyFile), UTF_8), InsecureSecretKeyAccess.get());

    if (mode.equals("sign")) {
      // Get the primitive.
      PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

      // Use the primitive to sign data.
      byte[] signature = signer.sign(msg);
      Files.write(signatureFile, signature);
    } else {
      byte[] signature = Files.readAllBytes(signatureFile);

      // Get the primitive.
      PublicKeyVerify verifier = handle.getPrimitive(PublicKeyVerify.class);

      verifier.verify(signature, msg);
    }
  }

  private SignatureExample() {}
}
// [END digital-signature-example]

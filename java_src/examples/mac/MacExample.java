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
// [START mac-example]
package mac;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.mac.MacConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A command-line utility for checking file integrity with a Message Authentication Code (MAC).
 *
 * <p>It loads cleartext keys from disk - this is not recommended!
 *
 * <p>It requires the following arguments:
 *
 * <ul>
 *   <li>mode: either 'compute' or 'verify'.
 *   <li>key-file: Read the key material from this file.
 *   <li>input-file: Read the input from this file.
 *   <li>mac-file: name of the file containing a hexadecimal MAC of the input data.
 */
public final class MacExample {
  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.printf("Expected 4 parameters, got %d\n", args.length);
      System.err.println("Usage: java MacExample compute/verify key-file input-file mac-file");
      System.exit(1);
    }
    String mode = args[0];
    if (!mode.equals("compute") && !mode.equals("verify")) {
      System.err.println("Incorrect mode. Please select compute or verify.");
      System.exit(1);
    }
    Path keyFile = Paths.get(args[1]);
    byte[] msg = Files.readAllBytes(Paths.get(args[2]));
    Path macFile = Paths.get(args[3]);

    // Register all MAC key types with the Tink runtime.
    MacConfig.register();

    // Read the keyset into a KeysetHandle.
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            new String(Files.readAllBytes(keyFile), UTF_8), InsecureSecretKeyAccess.get());

    // Get the primitive.
    Mac macPrimitive = handle.getPrimitive(Mac.class);

    if (mode.equals("compute")) {
      byte[] macTag = macPrimitive.computeMac(msg);
      Files.write(macFile, macTag);
    } else {
      byte[] macTag = Files.readAllBytes(macFile);
      // This will throw a GeneralSecurityException if verification fails.
      macPrimitive.verifyMac(macTag, msg);
    }
  }

  private MacExample() {}
}
// [END mac-example]

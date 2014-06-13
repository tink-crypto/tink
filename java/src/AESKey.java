/**
 * This class represents an AES key in K2. It allows you to encrypt and decrypt messaged using AES
 * symmetric key encryption
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class AESKey extends KeyVersion {
  // The key length in bytes (128 bits / 8 = 16 bytes)
  int keyLength = 16;
  // The actual key matter of the AES key.
  byte[] keyMatter = new byte[keyLength];
}

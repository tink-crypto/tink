import java.util.LinkedList;

/**
 * This class represents a Key in K2. It holds a list of KeyVersions and a reference to the primary
 * KeyVersion.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class Key {
  // The list of key versions
  LinkedList<KeyVersion> keyVersions = new LinkedList<KeyVersion>();
  KeyVersion primary;

  /**
   * Construct a Key with a single KeyVersion
   *
   * @param kv A KeyVersion to initialize the Key with
   */
  public Key(KeyVersion kv) {
    // Add the key version to the key
    this.keyVersions.add(kv);
    // set the primary to the key version (the only key version in the key)
    this.primary = kv;
  }
}

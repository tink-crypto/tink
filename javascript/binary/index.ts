import BinaryKeysetReader from 'goog:tink.BinaryKeysetReader'; // from //third_party/tink/javascript:binary_reader
import KeysetHandle from 'goog:tink.KeysetHandle'; // from //third_party/tink/javascript:keyset_handle_legacy

export function deserializeNoSecretKeyset(
    serializedKeyset: Uint8Array): KeysetHandle {
  return KeysetHandle.readNoSecret(
      BinaryKeysetReader.withUint8Array(serializedKeyset));
}

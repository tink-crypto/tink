import CleartextKeysetHandle from 'goog:tink.CleartextKeysetHandle'; // from //third_party/tink/javascript:cleartext_keyset_handle

export const deserializeKeyset = CleartextKeysetHandle.deserializeFromBinary;
export const serializeKeyset = CleartextKeysetHandle.serializeToBinary;

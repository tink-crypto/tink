import {CleartextKeysetHandle} from '../../internal/cleartext_keyset_handle';

export const deserializeKeyset = CleartextKeysetHandle.deserializeFromBinary;
export const serializeKeyset = CleartextKeysetHandle.serializeToBinary;

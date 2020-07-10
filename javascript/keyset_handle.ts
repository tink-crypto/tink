import KeysetHandle from 'goog:tink.KeysetHandle'; // from //third_party/tink/javascript:keyset_handle_legacy
import {PbKeyTemplate} from './internal/proto';
export {KeysetHandle};
export function generateNew(keyTemplate: PbKeyTemplate): Promise<KeysetHandle> {
  return KeysetHandle.generateNew(keyTemplate);
}

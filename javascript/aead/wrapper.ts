import * as Registry from '../internal/registry';
import {AeadWrapper} from './aead_wrapper';

export function register() {
  Registry.registerPrimitiveWrapper(new AeadWrapper());
}

import * as Registry from '../internal/registry';
import {AesGcmKeyManager} from './aes_gcm_key_manager';
import {AesGcmKeyTemplates} from './aes_gcm_key_templates';

export function register() {
  Registry.registerKeyManager(new AesGcmKeyManager());
}

export const aes128GcmKeyTemplate = AesGcmKeyTemplates.aes128Gcm;
export const aes256GcmKeyTemplate = AesGcmKeyTemplates.aes256Gcm;
export const aes256GcmNoPrefixKeyTemplate =
    AesGcmKeyTemplates.aes256GcmNoPrefix;

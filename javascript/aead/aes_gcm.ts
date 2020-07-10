import AesGcmKeyManager from 'goog:tink.aead.AesGcmKeyManager'; // from //third_party/tink/javascript/aead:aes_gcm_key_manager
import AesGcmKeyTemplates from 'goog:tink.aead.AesGcmKeyTemplates'; // from //third_party/tink/javascript/aead:aes_gcm_key_templates
import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy

export function register() {
  Registry.registerKeyManager(new AesGcmKeyManager());
}

export const aes128GcmKeyTemplate = AesGcmKeyTemplates.aes128Gcm;
export const aes256GcmKeyTemplate = AesGcmKeyTemplates.aes256Gcm;
export const aes256GcmNoPrefixKeyTemplate =
    AesGcmKeyTemplates.aes256GcmNoPrefix;

import AesCtrHmacAeadKeyManager from 'goog:tink.aead.AesCtrHmacAeadKeyManager'; // from //third_party/tink/javascript/aead:aes_ctr_hmac_aead_key_manager
import AesCtrHmacAeadKeyTemplates from 'goog:tink.aead.AesCtrHmacAeadKeyTemplates'; // from //third_party/tink/javascript/aead:aes_ctr_hmac_aead_key_templates
import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy

export function register() {
  Registry.registerKeyManager(new AesCtrHmacAeadKeyManager());
}

export const aes128CtrHmacSha256KeyTemplate =
    AesCtrHmacAeadKeyTemplates.aes128CtrHmacSha256;
export const aes256CtrHmacSha256KeyTemplate =
    AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256;

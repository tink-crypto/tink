import HybridDecryptWrapper from 'goog:tink.hybrid.HybridDecryptWrapper'; // from //third_party/tink/javascript/hybrid:hybrid_wrappers
import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy

export function register() {
  Registry.registerPrimitiveWrapper(new HybridDecryptWrapper());
}

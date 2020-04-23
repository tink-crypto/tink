import * as ecdsaForSigning from './ecdsa_for_signing';
import * as ecdsaForVerifying from './ecdsa_for_verifying';
import * as signWrapper from './sign_wrapper';
import * as verifyWrapper from './verify_wrapper';

export * from './sign';
export * from './verify';
export {ecdsaP256IeeeEncodingKeyTemplate, ecdsaP256KeyTemplate, ecdsaP384IeeeEncodingKeyTemplate, ecdsaP384KeyTemplate, ecdsaP521IeeeEncodingKeyTemplate, ecdsaP521KeyTemplate} from './ecdsa_for_signing';

export function register() {
  ecdsaForSigning.register();
  ecdsaForVerifying.register();
  signWrapper.register();
  verifyWrapper.register();
}

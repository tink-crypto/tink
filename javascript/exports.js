// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.exports');

const Aead = goog.require('tink.Aead');
const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const BinaryKeysetWriter = goog.require('tink.BinaryKeysetWriter');
const CryptoFormat = goog.require('tink.CryptoFormat');
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const KeysetReader = goog.require('tink.KeysetReader');
const KeysetWriter = goog.require('tink.KeysetWriter');
const Mac = goog.require('tink.Mac');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const PublicKeySign = goog.require('tink.PublicKeySign');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const Registry = goog.require('tink.Registry');

goog.exportSymbol('tink.Aead', Aead);
goog.exportSymbol('tink.BinaryKeysetReader', BinaryKeysetReader);
goog.exportSymbol('tink.BinaryKeysetWriter', BinaryKeysetWriter);
goog.exportSymbol('tink.CryptoFormat', CryptoFormat);
goog.exportSymbol('tink.HybridDecrypt', HybridDecrypt);
goog.exportSymbol('tink.HybridEncrypt', HybridEncrypt);
goog.exportSymbol('tink.KeyManager', KeyManager.KeyManager);
goog.exportSymbol('tink.KeyFactory', KeyManager.KeyFactory);
goog.exportSymbol('tink.PrivateKeyFactory', KeyManager.PrivateKeyFactory);
goog.exportSymbol('tink.KeysetHandler', KeysetHandle);
goog.exportSymbol('tink.KeysetReader', KeysetReader);
goog.exportSymbol('tink.KeysetWriter', KeysetWriter);
goog.exportSymbol('tink.Mac', Mac);
goog.exportSymbol('tink.Entry', PrimitiveSet.Entry);
goog.exportSymbol('tink.PrimitiveSet', PrimitiveSet.PrimitiveSet);
goog.exportSymbol('tink.PrimitiveWrapper', PrimitiveWrapper);
goog.exportSymbol('tink.PublicKeySign', PublicKeySign);
goog.exportSymbol('tink.PublicKeyVerify', PublicKeyVerify);
goog.exportSymbol('tink.Registry', Registry);

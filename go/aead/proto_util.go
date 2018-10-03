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

package aead

import (
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
)

// NewAESGCMKey returns a new AESGCMKey.
func NewAESGCMKey(version uint32, keyValue []byte) *gcmpb.AesGcmKey {
	return &gcmpb.AesGcmKey{
		Version:  version,
		KeyValue: keyValue,
	}
}

// NewAESGCMKeyFormat returns a new AESGCMKeyFormat.
func NewAESGCMKeyFormat(keySize uint32) *gcmpb.AesGcmKeyFormat {
	return &gcmpb.AesGcmKeyFormat{
		KeySize: keySize,
	}
}

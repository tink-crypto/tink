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

package daead

import tinkpb "github.com/google/tink/go/proto/tink_go_proto"

// AESSIVKeyTemplate is a KeyTemplate that generates a AES-SIV key.
func AESSIVKeyTemplate() *tinkpb.KeyTemplate {
	return &tinkpb.KeyTemplate{
		// Don't set value because KeyFormat is not required.
		TypeUrl:          aesSIVTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_TINK,
	}
}

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

package mac_test

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hmacpb "github.com/google/tink/go/proto/hmac_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestTemplates(t *testing.T) {
	template := mac.HMACSHA256Tag128KeyTemplate()
	if err := checkTemplate(template, 32, 16, commonpb.HashType_SHA256); err != nil {
		t.Errorf("incorrect HMACSHA256Tag128KeyTemplate: %s", err)
	}
	template = mac.HMACSHA256Tag256KeyTemplate()
	if err := checkTemplate(template, 32, 32, commonpb.HashType_SHA256); err != nil {
		t.Errorf("incorrect HMACSHA256Tag256KeyTemplate: %s", err)
	}
	template = mac.HMACSHA512Tag256KeyTemplate()
	if err := checkTemplate(template, 64, 32, commonpb.HashType_SHA512); err != nil {
		t.Errorf("incorrect HMACSHA512Tag256KeyTemplate: %s", err)
	}
	template = mac.HMACSHA512Tag512KeyTemplate()
	if err := checkTemplate(template, 64, 64, commonpb.HashType_SHA512); err != nil {
		t.Errorf("incorrect HMACSHA512Tag512KeyTemplate: %s", err)
	}
}

func checkTemplate(template *tinkpb.KeyTemplate,
	keySize uint32,
	tagSize uint32,
	hashType commonpb.HashType) error {
	if template.TypeUrl != testutil.HMACTypeURL {
		return fmt.Errorf("TypeUrl is incorrect")
	}
	format := new(hmacpb.HmacKeyFormat)
	if err := proto.Unmarshal(template.Value, format); err != nil {
		return fmt.Errorf("unable to unmarshal serialized key format")
	}
	if format.KeySize != keySize ||
		format.Params.Hash != hashType ||
		format.Params.TagSize != tagSize {
		return fmt.Errorf("KeyFormat is incorrect")
	}
	return nil
}

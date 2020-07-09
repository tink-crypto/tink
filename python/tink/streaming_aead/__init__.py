# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""StreamingAead package."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.streaming_aead import _decrypting_stream
from tink.streaming_aead import _encrypting_stream
from tink.streaming_aead import _streaming_aead
from tink.streaming_aead import _streaming_aead_key_manager
from tink.streaming_aead import _streaming_aead_key_templates as streaming_aead_key_templates


StreamingAead = _streaming_aead.StreamingAead
DecryptingStream = _decrypting_stream.DecryptingStream
EncryptingStream = _encrypting_stream.EncryptingStream
key_manager_from_cc_registry = _streaming_aead_key_manager.from_cc_registry
register = _streaming_aead_key_manager.register

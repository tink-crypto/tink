# Copyright 2019 Google LLC
#
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

"""Hybrid package."""

from tink.hybrid import _hybrid_decrypt
from tink.hybrid import _hybrid_encrypt
from tink.hybrid import _hybrid_key_manager
from tink.hybrid import _hybrid_key_templates as hybrid_key_templates


HybridDecrypt = _hybrid_decrypt.HybridDecrypt
HybridEncrypt = _hybrid_encrypt.HybridEncrypt
register = _hybrid_key_manager.register

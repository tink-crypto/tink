# Copyright 2023 Google LLC
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
"""HashiCorp Vault KMS integration package."""

try:
  # pylint: disable=g-import-not-at-top
  from tink.integration.hcvault import _hcvault_kms_aead
except ImportError as import_error:
  raise ImportError(
      'Error importing the Tink HashiCorp Vault KMS module; did you forget to'
      ' install the `tink[hcvault]` extras?'
  ) from import_error

new_aead = _hcvault_kms_aead.new_aead

# Copyright 2020 Google LLC
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
"""AWS KMS integration package."""

try:
  # pylint: disable=g-import-not-at-top
  from tink.integration.awskms import _aws_kms_client
except ImportError as import_error:
  raise ImportError(
      'Error importing the Tink AWS KMS module; did you forget to install the'
      ' `tink[awskms]` extras?'
  ) from import_error

AwsKmsClient = _aws_kms_client.AwsKmsClient

new_client = _aws_kms_client.new_client

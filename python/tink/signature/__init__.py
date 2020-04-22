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

"""Signature package."""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function


from tink.signature import _public_key_sign
from tink.signature import _public_key_verify
from tink.signature import _signature_key_manager
from tink.signature import _signature_key_templates as signature_key_templates


PublicKeySign = _public_key_sign.PublicKeySign
PublicKeyVerify = _public_key_verify.PublicKeyVerify
register = _signature_key_manager.register

"""Tink package."""
from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

from google3.third_party.tink.python import aead
from google3.third_party.tink.python import core
from google3.third_party.tink.python import daead
from google3.third_party.tink.python import hybrid
from google3.third_party.tink.python import mac
from google3.third_party.tink.python import signature
from google3.third_party.tink.python.core import tink_config


Aead = aead.Aead
DeterministicAead = daead.DeterministicAead
HybridDecrypt = hybrid.HybridDecrypt
HybridEncrypt = hybrid.HybridEncrypt
Mac = mac.Mac
PublicKeySign = signature.PublicKeySign
PublicKeyVerify = signature.PublicKeyVerify

KeyManager = core.KeyManager
PrivateKeyManager = core.PrivateKeyManager

Registry = core.Registry

new_keyset_handle = core.new_keyset_handle
read_keyset_handle = core.read
KeysetHandle = core.KeysetHandle


KeysetReader = core.KeysetReader
JsonKeysetReader = core.JsonKeysetReader
BinaryKeysetReader = core.BinaryKeysetReader

KeysetWriter = core.KeysetWriter
JsonKeysetWriter = core.JsonKeysetWriter
BinaryKeysetWriter = core.BinaryKeysetWriter

new_primitive_set = core.new_primitive_set

TinkError = core.TinkError

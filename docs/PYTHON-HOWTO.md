# Tink for Python HOW-TO

This document presents instructions and Python code snippets for common tasks in
[Tink](https://github.com/google/tink).

## Setup instructions

The Tink Python implementation is a wrapper around the C++ implementation using
[pybind11](https://github.com/pybind/pybind11). It is therefore necessary to
compile the project before the Python implementation is ready to use.

### Build with Bazel

[Bazel](https://bazel.io) is used to build and test Tink.

To build the Python implementation:

```shell
cd python
bazel build ...
```

### Build a Python package using pip

A setup script is provided which allows building a Python package using pip.

The setup script requires:

 * Bazel
 * [protobuf compiler](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation).

To build and install the Python package:

```shell
cd python
pip3 install .
```

### Running tests

To run all tests, you can:

```shell
cd python
bazel test ...
```


## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all standard implementations of all primitives
in the current release of Tink, the initialization would look as follows:

```python
import tink
from tink import tink_config
tink_config.register()
```

To use standard implementations of only one primitive, say AEAD:

```python
import tink
from tink import aead
aead.register()
```

The registration of custom key managers can proceed directly via
the `core.Registry` class:

```python
import tink
from tink import core
core.Registry.register_key_manager(CustomAeadKeyManager())
```

## Generating new keys and keysets

Each `KeyManager` implementation provides a `new_key_data(key_template)` method
that generates new keys of the corresponding key type.  However, to avoid
accidental leakage of sensitive key material you should avoid mixing key(set)
generation with key(set) usage in code.

To support the separation between these activities Tink package provides a
command-line tool called [Tinkey](TINKEY.md), which can be used for common key
management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Python code, you can use `tink.new_keyset_handle`:

```python
import tink
from tink import aead

key_template = aead.aead_key_templates.AES128_EAX
keyset_handle = tink.new_keyset_handle(key_template)
# use the keyset...
```

where `key_template` can be obtained from util classes corresponding to Tink
primitives, e.g.
[mac_key_templates](https://github.com/google/tink/blob/master/python/tink/mac/_mac_key_templates.py),
[aead_key_templates](https://github.com/google/tink/blob/master/python/tink/aead/_aead_key_templates.py),
or
[hybrid_key_templates](https://github.com/google/tink/blob/master/python/tink/hybrid/_hybrid_key_templates.py).

## Loading existing keysets

To load encrypted keysets, use `tink.read_keyset_handle`
and an appropriate [`KeysetReader`](https://github.com/google/tink/blob/master/python/tink/_keyset_reader.py),
depending on the wire format of the stored keyset, for example a
`tink.BinaryKeysetReader` or a `tink.JsonKeysetReader`.

```python
import tink

json_encrypted_keyset = ...
reader = tink.JsonKeysetReader(json_encrypted_keyset)
keyset_handle = tink.read_keyset_handle(reader, master_key_aead)
```

To load cleartext keysets, use [`cleartext_keyset_handle`](https://github.com/google/tink/blob/master/python/tink/cleartext_keyset_handle.py)
and an appropriate `KeysetReader`.

```python
import tink
from tink import cleartext_keyset_handle

json_keyset = ...
reader = tink.JsonKeysetReader(json_keyset)
keyset_handle = cleartext_keyset_handle.read(reader)
```
## Obtaining and using primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of the Tink API. A primitive is just an interface
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and you choose a desired implementation by using
a key of corresponding type (see [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for further details).

Tink for Python supports the same primitives as Tink for C++. A list of
primitives and their implementations currently supported by Tink in C++ can be
found [here](PRIMITIVES.md#c).

You obtain a primitive by calling the method `primitive` of the `KeysetHandle`.

### Symmetric key encryption

You can obtain and use an [AEAD (Authenticated Encryption with Associated
Data)](PRIMITIVES.md#authenticated-encryption-with-associated-data) primitive to
encrypt or decrypt data:

```python
# 1. Get a handle to the key material.
keyset_handle = ...

# 2. Get the primitive.
aead_primitive = keyset_handle.primitive(aead.Aead)

# 3. Use the primitive.
ciphertext = aead_primitive.encrypt(plaintext, associated data)
```

### Envelope encryption

Via the AEAD interface, Tink supports
[envelope encryption](KEY-MANAGEMENT.md#envelope-encryption).

For example, you can perform envelope encryption with a Google Cloud KMS key at
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
using the credentials in `credentials.json` as follows:

```python
  import tink
  from google3.third_party.tink.python.tink import aead
  from google3.third_party.tink.python.tink.integration import gcpkms

  key_uri = 'gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar'
  gcp_credentials = 'credentials.json'

  # Read the GCP credentials and setup client
  try:
    gcp_client = gcpkms.GcpKmsClient(key_uri, gcp_credentials)
    gcp_aead = gcp_client.get_aead(key_uri)
  except tink.TinkError as e:
    logging.error('Error initializing GCP client: %s', e)
    return 1

  # Create envelope AEAD primitive using AES256 GCM for encrypting the data
  try:
    key_template = aead.aead_key_templates.AES256_GCM
    env_aead = aead.KmsEnvelopeAead(key_template, gcp_aead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1
  # Use env_aead to encrypt data
  ciphertext = env_aead.encrypt(plaintext, associated data)
```

This folder contains protobuf definitions.

The subfolders (e.g., aes_gcm_go_proto) contain Go auto-generated code of the
protobuf definitions. These files facilitate using `go get` to install the Tink
library. This is only applicable outside of google3. To update them, execute the
following script:

```shell
$ g4d tink
$ ./third_party/tink/tools/gen_pb_go.sh
```

The script performs a Blaze query for the current Go proto dependencies,
generates the required files.

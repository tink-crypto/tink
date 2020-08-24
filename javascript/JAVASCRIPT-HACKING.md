# Hacking Tink for TypeScript/JavaScript

## Building Tink

*   Install [Bazel](https://docs.bazel.build/versions/master/install.html).
    Bazel is the exclusive build system for Tink for TypeScript/JavaScript
    (although you don't need it to merely depend on the `tink-crypto` package
    from npm, only to build from source).

*   Check out source code and run `bazel build`. It will download dependencies
    and do all the other npm-related stuff automatically.

## Updating Dependencies

*   Dependency versions are specified in `package.json`.
*   After changing dependencies in `package.json`, run `yarn` (or, if you don't
    have the Yarn CLI installed globally, `npx yarn`) to update `yarn.lock`.

## Protocol Buffers

We're currently using a pretty ad-hoc method of depending on protos from
TypeScript code; it involves feeding the output from one build toolchain into a
different one. The implementation is in `internal/ts_library_from_closure.bzl`.
Note that it's also necessary to add any new protos to `internal/BUILD.bazel`.

## Code Splitting

There's no support for code splitting right now; `index.ts` is the sole entry
point and everything has to be directly or indirectly exported from there.

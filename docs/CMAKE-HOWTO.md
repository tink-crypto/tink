# CMake for Tink HOW-TO

# Incorporating Tink into your project

If you are developing a project that uses Tink, you might incorporate the
library following one of the following approaches. At the moment, only the
in-tree dependency is supported, although all of them should work.

## In-tree dependency

Tink can be embedded directly in your CMake project and statically linked in
your executable. This is the approach we currently recommend. Assuming the Tink
source tree has been copied in the `third_party/tink` directory of your project,
your top-level CMake script should look like this:

    cmake_minimum_required(VERSION 3.5)
    project(YourProject CXX)
    set(CMAKE_CXX_STANDARD 11)

    add_subdirectory(third_party/tink)

    add_executable(your_app your_app.cc)
    target_link_libraries(your_app tink::static)

NOTE: You need at least CMake 3.5 to build Tink and its dependencies.

Include Tink headers in `your_app.cc` as follows:

    #include "tink/config.h"
    #include "tink/json_keyset_reader.h"

    // ...

NOTE: `tink::static` provides the `tink/...` include path. It is just a shortcut
for your convenience, and you might still refer to Tink headers using a
filesystem path, such as `third_party/tink/cc/...`, if you prefer or need to.

You can see a full example in `examples/helloworld/cc/hello_world.cc`.

Generate the build directory as you normally would and invoke your build system
of choice:

    $ ls
    CMakeLists.txt your_app.cc third_party/
    $ mkdir build && cd build
    $ cmake ..
    $ make
    $ ./your_app

If you have the option, we recommend using [Ninja](https://ninja-build.org/) to
build your project:

    $ cmake -DCMAKE_GENERATOR=Ninja ..
    $ ninja

## Stand-alone libtink.so

Alternatively, you may build `libtink.so` on Linux and Darwin systems. This
feature is disabled by default, and is currently not supported on Windows. You
can enable it at configure time:

    $ ls
    tink/
    $ mkdir tink-build && cd tink-build
    $ cmake ../tink -DTINK_BUILD_SHARED_LIB=ON
    $ make package

We recommend using Ninja in this case too:

    $ cmake ../tink -DTINK_BUILD_SHARED_LIB=ON -DCMAKE_GENERATOR=Ninja
    $ ninja package

This produces a `.tar.gz` archive containing `libtink.so`, all Tink headers and
some extra support headers. This is a stand-alone build that you can integrate
in your own process.

WARNING: Setting `TINK_BUILD_SHARED_LIB` to `ON` is not recommended in
combination with the in-tree dependency approach, as this option causes several
`install` targets to be created, which will pollute your own install.

## libtink.so CMake config

Building `libtink.so` also writes a CMake config to the build directory,
`TinkConfig.cmake`. You can use it with `find_package` in `CONFIG` mode to
import the `tink` target in your project without embedding all of Tink internal
targets in your CMake build. In this case you have to provide your own system
for building and keeping `libtink.so` up to date.

NOTE: We currently only export `libtink.so` as `tink`. We are working on a way
to provide `tink::static` too.

# Developing Tink with CMake

If you are developing Tink, Bazel is the primary build system, but you should
test all your changes with CMake too. Build Tink as a regular CMake project, but
enable tests and build the shared library as well:

    $ ls
    tink/
    $ mkdir tink-build && cd tink-build
    $ cmake ../tink -DTINK_BUILD_SHARED_LIB=ON -DTINK_BUILD_TESTS=ON -DCMAKE_GENERATOR=Ninja
    $ ninja
    $ CTEST_OUTPUT_ON_FAILURE=1 ninja test
    $ ninja package

This combination of options ensures that the entire CMake configuration is
evaluated.

WARNING: When editing a `BUILD.bazel` file, remember to keep it in sync with the
corresponding `CMakeLists.txt` file.

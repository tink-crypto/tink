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
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_STANDARD 11)

    add_subdirectory(third_party/tink)

    add_executable(your_app your_app.cc)
    target_link_libraries(your_app tink::static)

NOTES:

*   You need at least CMake 3.5 to build Tink and its dependencies.
*   Tink defines the C++ standard to use via the `TINK_CXX_STANDARD` variable,
    which is `11` by default. If you want to propagate to the value of
    `CMAKE_CXX_STANDARD` to Tink use `set(CMAKE_CXX_STANDARD_REQUIRED ON)`.

Include Tink headers in `your_app.cc` as follows:

    #include "tink/config.h"
    #include "tink/json_keyset_reader.h"

    // ...

NOTE: `tink::static` provides the `tink/...` include path. It is just a shortcut
for your convenience, and you might still refer to Tink headers using a
filesystem path, such as `third_party/tink/cc/...`, if you prefer or need to.

You can see a full example in `examples/cc/helloworld/hello_world.cc`.

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


# Developing Tink with CMake

If you are developing Tink, Bazel is the primary build system, but you should
test all your changes with CMake too. Build Tink as a regular CMake project, but
enable tests and build the shared library as well:

    $ ls
    tink/
    $ mkdir tink-build && cd tink-build
    $ cmake ../tink -DTINK_BUILD_TESTS=ON -DCMAKE_GENERATOR=Ninja
    $ ninja
    $ CTEST_OUTPUT_ON_FAILURE=1 ninja test
    $ ninja package

This combination of options ensures that the entire CMake configuration is
evaluated.

WARNING: When editing a `BUILD.bazel` file, remember to keep it in sync with the
corresponding `CMakeLists.txt` file.

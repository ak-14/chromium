# Getting Started with libprotobuf-mutator in Chromium

*** note
**Note:** libprotobuf-mutator (LPM) is new to Chromium and does not (yet) have a
long track record of success. Also, writing grammar fuzzers with
libprotobuf-mutator requires greater effort than writing fuzzers with libFuzzer
alone. If you run into problems, send an email to [fuzzing@chromium.org] for
help.

**Prerequisites:** Knowledge of [libFuzzer in Chromium] and basic understanding of
[Protocol Buffers].
***

This document will walk you through:

* An overview of libprotobuf-mutator and how it's used.
* Writing and building your first fuzzer using libprotobuf-mutator.

## Overview of libprotobuf-mutator
libprotobuf-mutator is a package that allows libFuzzer’s mutation engine to
manipulate protobufs. This allows libFuzzer's mutations to be more specific
to the format it is fuzzing and less arbitrary. Below are some good use cases
for libprotobuf-mutator:

* Fuzzing targets that accept Protocol Buffers as input. See the next section
for how to do this.
* Fuzzing targets that accept input defined by a grammar. To do this you
must write code that converts data from a protobuf-based format that represents
the grammar to a format the target accepts. url_parse_proto_fuzzer is a working
example of this and is commented extensively. Readers may wish to consult its
code, which is located in `testing/libfuzzer/fuzzers/url_parse_proto_fuzzer.cc`,
and `testing/libfuzzer/fuzzers/url.proto`. Its build configuration can be found
in `testing/libfuzzer/fuzzers/BUILD.gn`. We also provide a walkthrough on how to
do this in the section after the next.
* Fuzzing targets that accept more than one argument (such as data and flags).
In this case, you can define each argument as its own field in your protobuf
definition.

In the next section, we discuss building a fuzzer that targets code that accepts
an already existing protobuf definition. In the section after that, we discuss
how to write and build grammar-based fuzzers using libprotobuf-mutator.
Interested readers may also want to look at [this] example of a
libprotobuf-mutator fuzzer that is even more trivial than
url_parse_proto_fuzzer.

## Write a fuzzer for code that accepts protobufs
This is almost as easy as writing a standard libFuzzer-based fuzzer. You can
look at [override_lite_runtime_plugin_test_fuzzer] for an example of a working example of
this (don't copy the line adding "//testing/libfuzzer:no_clusterfuzz" to
additional_configs). Or you can follow this walkthrough:

Start by creating a fuzz target. This is what the .cc file will look like:

```c++
// my_fuzzer.cc

#include "testing/libfuzzer/proto/lpm_interface.h"

// Assuming the .proto file is path/to/your/proto_file/my_proto.proto.
#include "path/to/your/proto_file/my_proto.pb.h"

DEFINE_BINARY_PROTO_FUZZER(
  const my_proto::MyProtoMessage& my_proto_message) {
  targeted_code(my_proto_message);
}
```

The BUILD.gn definition for this target will be very similar to regular
libFuzzer-based fuzzer_test. However it will also have libprotobuf-mutator in
its deps. This is an example of what it will look like:

```python
// You must wrap the target in "use_libfuzzer" since trying to compile the
// target without use_libfuzzer will fail (for reasons alluded to in the next
// step), which the commit queue will try.
if (use_libfuzzer) {
  fuzzer_test("my_fuzzer") {
    sources = [ "my_fuzzer.cc" ]
    deps = [
      // The proto library defining the message accepted by
      // DEFINE_BINARY_PROTO_FUZZER().
      ":my_proto",

      "//third_party/libprotobuf-mutator",
      ...
    ]
  }
}
```

There's one more step however. Because Chromium doesn't want to ship to users
the full protobuf library, all `.proto` files in Chromium that are used in
production contain this line: `option optimize_for = LITE_RUNTIME` But this
line is incompatible with libprotobuf-mutator. Thus, we need to modify the
`proto_library` build target so that builds when fuzzing are compatible with
libprotobuf-mutator. We do this by using a protobuf compiler plugin,
`override_lite_runtime_plugin`. Here's what a `proto_library` build target that
is configured properly looks like:

```python
proto_library("my_proto") {
  ... // These lines (probably) dont need to be changed.

  if (use_libfuzzer && current_toolchain == host_toolchain) {
    generator_plugin_label =
      "//third_party/libprotobuf-mutator:override_lite_runtime_plugin"
    generator_plugin_suffix = ".pb"
    # The plugin will generate cc, so don't ask for it to be done by protoc.
    generate_cc = false
    // If deps is already defined, change "=" to "+=".
    deps = ["//third_party/libprotobuf-mutator:override_lite_runtime_plugin"]
  }
}
```

Note that this will not have any affects on the proto_library in production,
since the plugin is only used when `use_libfuzzer == true`.
And with that we have completed writing a libprotobuf-mutator fuzz target for
Chromium code that accepts protobufs.


## Write a grammar-based fuzzer with libprotobuf-mutator

Once you have in mind the code you want to fuzz and the format it accepts, you
are ready to start writing a libprotobuf-mutator fuzzer. Writing the fuzzer
will have three steps:

* Define the fuzzed format (not required for protobuf formats, unless the
original definition is optimized for `LITE_RUNTIME`).
* Write the fuzz target and conversion code (for non-protobuf formats).
* Define the GN target

### Define the Fuzzed Format
Create a new .proto using `proto2` or `proto3` syntax and define a message that
you want libFuzzer to mutate.

``` protocol-buffer
syntax = "proto2";

package my_fuzzer;

message MyProtoFormat {
    // Define a format for libFuzzer to mutate here.
}
```

See `testing/libfuzzer/fuzzers/url.proto` for an example of this in practice.
That example has extensive comments on URL syntax and how that influenced
the definition of the Url message.

### Write the Fuzz Target and Conversion Code
Create a new .cc and write a `DEFINE_BINARY_PROTO_FUZZER` function:

```c++
// Needed since we use getenv().
#include <stdlib.h>

// Needed since we use std::cout.
#include <iostream>

#include "testing/libfuzzer/proto/lpm_interface.h"

// Assuming the .proto file is path/to/your/proto_file/my_format.proto.
#include "path/to/your/proto_file/my_format.pb.h"

// Put your conversion code here (if needed) and then pass the result to
// your fuzzing code (or just pass "my_format", if your target accepts
// protobufs).

DEFINE_BINARY_PROTO_FUZZER(const my_fuzzer::MyFormat& my_proto_format) {
    // Convert your protobuf to whatever format your targeted code accepts
    // if it doesn't accept protobufs.
    std::string native_input = convert_to_native_input(my_proto_format);

    // You should provide a way to easily retreive the native input for
    // a given protobuf input. This is useful for debugging and for seeing
    // the inputs that cause targeted_code to crash (which is the reason we are
    // here!). Note how this is done before the targeted_code is called since we
    // can't print after the program has crashed.
    if (getenv("LPM_DUMP_NATIVE_INPUT"))
      std::cout << native_input << std::endl;

    // Now test your targeted code using the converted protobuf input.
    targeted_code(native_input);
}
```

This is very similar to the same step in writing a standard libFuzzer fuzzer.
The only real differences are accepting protobufs rather than raw data and
converting them to the desired format. Conversion code can't really be explored
in this guide since it is format-specific. However, a good example of conversion
code (and a fuzz target) can be found in
`testing/libfuzzer/fuzzers/url_parse_proto_fuzzer.cc`. That example thoroughly
documents how it converts the Url protobuf message into a real URL string.
Note that `DEFINE_TEXT_PROTO_FUZZER` can be used during development instead of
`DEFINE_BINARY_PROTO_FUZZER`. `DEFINE_TEXT_PROTO_FUZZER` comes with a
performance penalty but causes the corpus to be stored in a human readable (and
modifiable) string-based format.
A good convention is printing the native input when the `LPM_DUMP_NATIVE_INPUT`
env variable is set. This will make it easy to retreive the actual input that
causes the code to crash instead of the protobuf version of it (eg you can get
the URL string that causes an input to crash rather than a protobuf). Since it
is only a convention it is strongly recommended even though it isn't necessary.
You don't need to do this if the native input of targeted_code is protobufs.
Beware that printing a newline can make the output invalid for some formats. In
this case you should use `fflush(0)` since otherwise the program may crash
before native_input is actually printed.


### Define the GN Target
Define a fuzzer_test target and include your protobuf definition and
libprotobuf-mutator as dependencies.

```python
import("//testing/libfuzzer/fuzzer_test.gni")
import("//third_party/protobuf/proto_library.gni")

fuzzer_test("my_fuzzer") {
  sources = [ "my_fuzzer.cc" ]
  deps = [
    ":my_format_proto",
    "//third_party/libprotobuf-mutator"
    ...
  ]
}

proto_library("my_format_proto") {
  sources = [ "my_format.proto" ]
}
```

See `testing/libfuzzer/fuzzers/BUILD.gn` for an example of this in practice.

### Tips For Grammar Based Fuzzers
* If you have messages that are defined recursively (eg: message `Foo` has a
field of type `Foo`), make sure to bound recursive calls to code converting
your message into native input. Otherwise you will (probably) end up with an
out of memory error. The code coverage benefits of allowing unlimited
recursion in a message are probably fairly low for most targets anyway.

* Remember that proto definitions can be changed in ways that are backwards
compatible (such as adding explicit values to an `enum`). This means that you
can make changes to your definitions while preserving the usefulness of your
corpus. In general adding fields will be backwards compatible but removing them
(particulary if they are `required`) is not.

* Make sure you understand the meaning of the different protobuf modifiers such
as `oneof` and `repeated` as they can be counter-intuitive. `oneof` means "At
most one of" while `repeated` means "At least zero". You can hack around these
meanings if you need "at least one of" or "exactly one of" something. For
example, this is the proto code for exactly one of: `MessageA` or `MessageB` or
`MessageC`:

```protocol-buffer
message MyFormat {
    oneof a_or_b {
      MessageA message_a = 1;
      MessageB message_b = 2;
    }
    required MessageC message_c = 3;
}
```

And here is the C++ code that converts it.

```c++
std::string Convert(const MyFormat& my_format) {
  if (my_format.has_message_a())
    return ConvertMessageA(my_format.message_a());
  else if (my_format.has_message_b())
    return ConvertMessageB(my_format.message_b());
  else // Fall through to the default case, message_c.
    return ConvertMessageC(my_format.message_c());
}
```

* libprotobuf-mutator supports both proto2 and proto3 syntax. Be aware though
that it handles strings differently in each because of differences in the way
the proto library handles strings in each syntax (in short, proto3 strings must
actually be UTF-8 while in proto2 they do not). See [here] for more details.

## Wrapping Up
Once you have written a fuzzer with libprotobuf-mutator, building and running
it is pretty much the same as if the fuzzer were a standard libFuzzer-based
fuzzer (with minor exceptions, like your seed corpus must be in protobuf
format).

## General Tips
* Check out some of the [existing proto fuzzers], as not only will they be helpful
examples, but it is possible that your format is already defined or partially
defined by an existing proto definition (if you are writing a grammar fuzzer).


[libfuzzer in Chromium]: getting_started.md
[Protocol Buffers]: https://developers.google.com/protocol-buffers/docs/cpptutorial
[fuzzing@chromium.org]: mailto:fuzzing@chromium.org
[this]: https://github.com/google/libprotobuf-mutator/tree/master/examples/libfuzzer/libfuzzer_example.cc
[existing proto fuzzers]: https://cs.chromium.org/search/?q=DEFINE_(BINARY_%7CTEXT_)?PROTO_FUZZER+-file:src/third_party/libprotobuf-mutator/src/src/libfuzzer/libfuzzer_macro.h&sq=package:chromium&type=cs
[here]: https://github.com/google/libprotobuf-mutator/blob/master/README.md#utf-8-strings
[override_lite_runtime_plugin_test_fuzzer]: https://cs.chromium.org/chromium/src/third_party/libprotobuf-mutator/BUILD.gn?l=78

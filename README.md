# cargo-shellcode

Compile your Rust project[^1] into shellcode for use in CTF or exploit development!

The subcommand runs an LLVM pass over your code which inlines all functions into the entrypoint,
and moves all globals into stack space. This allows you to write mostly-normal-looking code which
can be used as shellcode.

![Example](asset/hello-world.gif)

## Install

```sh
cargo install cargo-shellcode
```

You will need to have LLVM installed (e.g. `dnf install llvm llvm-libs llvm-devel`).

## Usage

To build your crate as shellcode:

```sh
cargo shellcode build
```

Optionally, you can specify where to output the shellcode:

```sh
cargo shellcode build -o shellcode.bin
```

To run your shellcode (note: this is pretty unsafe!):

```sh
cargo shellcode run
```

Or to run a specific shellcode file:

```sh
cargo shellcode run shellcode.bin
```


## Crate Layout

Not just any crate can be compiled down to shellcode. In general, you'll need to follow these rules:

* The entrypoint must be called `_start` or `main`
* Your code must be `#![no_std]` and `#![no_main]`, and compatible with `-nostartfiles` (i.e. a freestanding binary)
* Globals/constants may only be used by one function. Basically:
    * Do not use `static` variables
    * Put all `const` values in the function that uses them, not in global scope

For an example of a crate that does something non-trivial that can be compiled to shellcode, check out [the examples](examples/hello-world/src/main.rs).

## Acknowledgements

This project (in particular the global variable inlining) is partially taken from and inspired by
[SheLLVM](https://github.com/SheLLVM/SheLLVM). Thanks!


[^1]: Some caveats apply, see [crate layout](#crate-layout).

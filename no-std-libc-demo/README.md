# `no-std-libc-demo`

This is a simple no-std rustls demo that, in principle, should run on any RTOS or OS that has a C library that's more or less POSIX compliant.
For convenience, this has been built to run on Linux as that can be tested in CI.
Should you wish to run this demo on some other OS, check the README in the `ministd` directory for porting instructions.

TODO document how to set up QEMU *if* we end up using the `aarch64-unknown-none` target

# `ministd`

Minimal port of libstd API to no-std land on top of `libc` for the purpose of demo-ing rustls on *non*-bare-metal no-std targets.

This library has only be tested and only supports aarch64 Linux + glibc 2.26+. 
There is no plan / intention to expand OS support but you are free to re-use this code on other OSes;
note that you'll need to update the `libc` module or use the `libc` crate on crates.io if it supports your no-std target.

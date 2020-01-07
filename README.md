libtrc
======

A C library to easily create "generic" (architecture independent) trace files
for [trcview](https://github.com/pekd/vmx86).

Usage
-----

Write your code, include `trace.h`, link it with `trace.c`. That's it.

Demo
----

The demo program `demo.c` creates a simple trace file with a few steps, memory
accesses and an mmap event.

Compile the demo with:
```c
gcc -o demo demo.c trace.c
```

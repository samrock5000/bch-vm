# Bitcoin Cash Virtual Machine

## Purpose
A coding exercise for implementing a virtual machine.

## cli app usage
In/Validates  [Bitauth's vmb_tests 2025](https://github.com/bitauth/vmb_tests/). You should be in the *vmb_test* direcory when running the app.

```
<identifier> <path>
```
```
$ verifyprogram 5xd04t bch_2025_standard
```

Prints:

Metrics:
sig checks: 4\
op cost: 4661\
hash iterations: 32\
Over operation limit: false\
Over hash limit: false\
Composite op cost: 114805


Performance Statistics:\
Total Execution Time: 28259000 ns\
Total Verification Time: 16015 us\
Average Verification Time: 16015 us\
Number of Verifications: 1\
Failed Verifications: 0\
Verification Rate: 62 ops/sec

### Verify all bch_2025_standard vmb test
This test expects the *vmb_tests* in ../vmb_test from the current working direcotry.
```
$ zig test -O ReleaseFast src/test.zig --test-filter vmbstandard2025

Prints:
```
__Naive Performance statistics same as above:__

## cli app debug usage

```
$ zig build -Dbuilder=debug
```

```
$ vmdebug lcg6dg bch_2023_standard
```

*****************************************
Next Operation: opcodes.Opcodes.op_checkdatasig\
Instruction Pointer: 200\
Stack:\
Index: 0\
Value: { 48, 69, 2, 33, 0, 213, 243, 175, 125, 241, 150, 76, 3, 253, 106, 162, 171, 115, 39, 13, 218, 79, 10, 144, 211, 229, 57, 100, 163, 62, 233, 186, 78, 87, 229, 174, 31, 2, 32, 94, 102, 240, 196, 240, 106, 94, 25, 139, 175, 96, 120, 117, 142, 58, 194, 190, 179, 139, 207, 205, 123, 129, 31, 41, 139, 168, 211, 8, 70, 213, 97 }\
Index: 1\
Value: { 223, 53, 241, 2, 238, 122, 204, 89, 127, 6, 101, 251, 9, 104, 89, 34, 144, 23, 230, 63, 64, 229, 4, 118, 236, 24, 35, 238, 218, 182, 15, 23 }\
Index: 2\
Value: { 3, 165, 36, 244, 61, 97, 102, 173, 53, 103, 241, 139, 10, 92, 118, 156, 106, 180, 220, 2, 20, 159, 77, 80, 149, 204, 244, 232, 255, 162, 147, 231, 133 }\
Alt Stack:\
Control Stack length: 0\
Metrics:\
sig checks: 7\
op cost: 4588\
hash iterations: 30\
Over operation limit: false\
Over hash limit: false\
Composite op cost: 192348
Press Enter to continue...
*****************************************



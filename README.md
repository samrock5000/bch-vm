# Bitcoin Cash Virtual Machine

## Purpose
A coding exercise for implementing a virtual machine.

Running on Zig 0.14.0-dev...

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






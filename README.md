# qh - Quick Hash

Provides an implementation of various non-cryptographic string hashing 
functions typically for use in a hash table. 

## Building

The program alone is a single source file with no external dependencies, 
so I hope you know how to use your toolchain of choice. Regardless, here
are some copy-pastable build commands. Feel free to contribute others
for your particular compiler.

### gcc

```
gcc -O2 -o qh qh.c
```

## Installing

Feel free to `mv` the build into any directory of your choosing on your
`$PATH`. I personally recommend `~/.local/bin`.

## Usage

Please reference `qh -h` for usage information.

## Contributing

Feel free to fix typos, add more algorithms, or new features as you see
fit. Just fork the repository and submit a pull request with your 
desired additions.

### Code

I request that, if you implement a new feature in code, you follow the
general styling already present in `qh.c`. I also request that no
additional source or header files be added to the project to keep it
simple. Thank you!

### Algorithms

If you want to contribute a new hash function, place the function
definition under the `Functions 32` or `Functions 64` banner comments
depending on the output size of the hash. Also make sure to add an
entry in the `algorithms` array describing the hash you have just
added. I request that you keep the formatting aligned with already
present entries, and make adjustments as necessary to keep the
symmetry for ease of reading.
# argon2
A C implementation of the [Password Hashing Competition](https://password-hashing.net/) winner [Argon2](https://github.com/p-h-c/phc-winner-argon2) hash function. Compared to the official implementation, the code tries to be clearer and easier to follow according to the algorithm [specifications](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf). 
The Argon2 version implemented is 0x13. The sources contain also an ad-hoc version of [blake2b](https://blake2.net/) used as internal hash function by Argon2.

The code is thought for academic purpose and is not optimized. 

## Makefile

`make` builds the executable `argon2` while `make clean` removes it. The [OpenMP](http://www.openmp.org/) library is needed to compile the sources.

On Linux systems `make` set `gcc` as default compiler, while on Mac OSX is set to `gcc-6`.

### Usage

The executable `argon2`runs a specific Argon2 instance. To show usage instructions, run
`./argon2` or `./argon2 -h`:

```
Usage: [-h] [-P password] [-S salt] [-K secret key] [-X associated data] [-m memory] [-t iterations] [-p parallelism] [-l hash length] [-i|-d] 

Parameters:
	-P pass		The password to hash, from 0 to 2^32-1 characters. (default NULL)
	-S salt		The salt to use, from 8 to 2^32-1 characters.
	-K key		The secret key, from 0 to 2^32-1 characters. (default NULL)
	-X data		The associated data, from 0 to 2^32-1 characters. (default NULL)
	-t N		  Sets the number of iterations to N. From 1 to 2^24-1. (default = 3)
	-m N		  Sets the memory usage to N KB. From 8p to 2^32-1. (default 4096)
	-p N		  Sets parallelism to N threads. From 1 to 2^32-1. (default 1)
	-l N		  Sets hash output length to N bytes. From 4 to 2^32-1. (default 32)
	-i		    Use Argon2i (this is the default)
	-d		    Use Argon2d instead of Argon2i
	-h		    Print help
```
For example, if you want to hash the string "password" using "somesalt" as a salt, doing 2 iterations, consuming 64 MB, using 4 parallel threads to get an output hash of 24 bytes, use:
```
$ ./argon2 -P "password" -S "somesalt" -t 2 -m 65536 -p 4 -l 24
=======================================
Argon2i version number 19
=======================================
Memory: 65536 KB (m': 65536), Iterations: 2, Parallelism: 4 lanes, Tag length: 24 bytes

Password[8]: 70 61 73 73 77 6f 72 64 
Salt[8]: 73 6f 6d 65 73 61 6c 74 
Secret[0]: 
Associated data[0]: 
Pre-hashing digest: 2c f2 4f b3 33 81 c1 b4 2d 79 be 2d 14 fe c2 af 26 24 2d d3 2a d2 50 88 73 fd 35 15 72 a7 02 11 44 0d 62 5a 1f 7a ab d0 46 bd 3f 1f 7d 82 e8 11 d5 51 5b e0 29 46 60 af 57 41 59 f1 17 bb 62 5e 

Tag: 45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
```

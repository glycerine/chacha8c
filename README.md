chacha8c
========

This is ChaCha8 ported from Go to C and C++.

ChaCha8 is the 8-round version of the ChaCha20 cryptographically strong 
pseudo-random number generator designed by Daniel J. Bernstein.

Details:

https://cr.yp.to/chacha.html
https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c

chacha-ref.c version 20080118 is marked as public domain.

ChaCha8 is meant for speed (2.5x speedup vs 20 rounds) in non-cryptographic applications.
The argument that it might still be suitable despite the reduced rounds is argued in:

"Too Much Crypto" by Jean-Philippe Aumasson
https://eprint.iacr.org/2019/1492.pdf
https://bfswa.substack.com/p/6-years-after-too-much-crypto

However, as Jean-Philippe says in the previous link,
"Daniel J. Bernstein, the designer of ChaCha20, finds 
it [ChaCha8] too risky [for actual cryptographic applications]".

reference:
https://cr.yp.to/talks/2025.03.24/slides-djb-20250324-mceliece-4x3.pdf

Hence, despite its origins in CSPRNG design, this library is only recommended for non-cryptographic
pseudo-random number generation needs such as runtime fairness, monte-carlo
simulation, or fuzz-testing. For example, recent Go runtimes use
ChaCha8 for the randomized choice of which "select" branch to choose
when more than one case can communicate.

# a note on performance

This implementation is aimed at portability rather than performance. 
Hence the C/C++ do not exploit assembly based SIMD optimizations. 

Go users should use the built in standard library math/rand/v2 ChaCha8 
to get SIMD/performance tuned versions. The output is identical. 
Our implementation matches the Go standard library implementation 
of ChaCha8. You can swap go_src/chacha8rand.go:46 
for line 47 and re-run make in the parent directory to confirm this.

---
Author: Jason E. Aten, Ph.D.

LICENSE: BSD 3-clause. Same as Go.

chacha8c
========

This is ChaCha8 ported from Go to C and C++.

ChaCha8 is a cryptographically strong random number generator designed by Daniel J. Bernstein.

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

---
Author: Jason E. Aten, Ph.D.

LICENSE: BSD 3-clause. Same as Go.

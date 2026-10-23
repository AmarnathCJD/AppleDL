# ALAC decryption performance

Measured on 2026-10-23 with an Intel Core i5-12500H (16 logical CPUs), Windows
amd64, Go runtime and CGO disabled. The worker sweep used the same 196.18-second,
24-bit/48 kHz stereo ALAC file and the same in-memory license contexts.

| Sample-pass workers | Median of 3 runs |
| --- | ---: |
| 8 | 2.6029 s |
| 12 | 2.2421 s |
| 16 | 1.9000 s |
| 20 | 1.9213 s |
| 24 | 1.9254 s |
| 32 | 1.8795 s |

The original sequential sample pass took 16.5666 s. The 16-worker median is about
8.7 times faster. Using 32 workers improved on 16 by only about 1.1%; it did not
reduce the pass below one second. The default remains `min(16, GOMAXPROCS)`.

Sample-pass timings include fragment I/O, but exclude network acquisition,
licensing, detached context setup (about 0.45 s combined on this fixture) and
worker cloning (about 1–2 ms). Total decryption includes those local setup costs;
complete download time also includes the network and licensing.

Portable Windows replay of the exported fixture took 2.0053 s for the sample
pass and 2.1090 s total. Its output matched the original byte for byte and passed
a complete strict FFmpeg decode.

A separate live 24-bit/44.1 kHz stereo track took 2.9295 s for 2,154 samples,
3.8524 s total local decryption, and 20.1738 s for metadata, acquisition,
licensing and decryption. Constructor authentication is excluded. Different
tracks and machines will have different timings.

Linux amd64 replay of the same exported fixture took 4.5177 s for the sample
pass and 5.2352 s total. Its output was byte-identical to Windows and passed
strict full-file decoding. The final Linux example run reused the portable
Windows session, acquired the separate 24-bit/44.1 kHz track with fresh licenses,
and completed 2,154 samples using 16 workers: 7.1924 s sample pass, 9.8516 s total
local decryption, 31.3774 s including metadata, acquisition and licensing.
Constructor authentication is excluded. The output passed strict decoding.

Linux runs used Debian under WSL with files on the mounted D: drive and some
concurrent build activity. They establish portability, not a controlled speed
comparison with Windows. All these paths ran with CGO disabled.

Workers own independent cloned state and write to validated, disjoint sample
ranges. Cancellation joins workers before erasing partial output. Generated
arithmetic is unchanged by the scheduling optimization.

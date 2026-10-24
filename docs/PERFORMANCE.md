# ALAC decryption performance

## Playback preparation optimization, 2026-10-24

Measured on the same Linux amd64 VPS (8 CPUs, 16 GB RAM), with Go 1.26.2,
CGO disabled and 16 decryption workers. Each run used the same 40,879,747-byte,
24-bit/44.1 kHz stereo ALAC track. Cold and warm refer to the first and second
preparation in one process; these are individual measurements, not medians.

| Elapsed stage | Before, cold / warm | After, cold / warm |
| --- | ---: | ---: |
| Complete preparation | 10.461 / 9.679 s | 4.521 / 3.654 s |
| Licensing | 5.971 / 5.577 s | 1.208 / 0.878 s |
| Local decryption | — | 2.056 / 1.979 s |
| Decryptor setup | — | 0.048 / 0.053 s |

Complete preparation here is measured by Tunly's client adapter: it includes
metadata, acquisition, licensing, decryption, remuxing and full-file decode
validation. It excludes constructor authentication and Telegram upload.
Acquisition and licensing now overlap, so their durations must not be added.
Per-key component counters sum work; licensing above is elapsed wall time.
Apple's license exchange accounted for about 0.54 / 0.57 seconds of work in
the final cold / warm runs. Sample processing took about 1.93 / 1.92 seconds.

The change compiles frequent licensing blocks to Go, preserves compiled
execution between the two decryptor observation points, and overlaps acquisition
with licensing. Independent license contexts are bounded to two workers; account
header preparation and license requests remain serialized. Cancellation joins
all started work before cleanup.

Validation compared all 8,448 compiled entries encountered during live playback
against the reference interpreter, checking registers, flags, scheduling counts
and mapped memory. This covers the observed inputs, not every possible input.
Both complete ALAC downloads decoded successfully. The client and Tunly test
suites passed. A subsequent Telegram smoke prepared the track in 4.495 seconds
and replaced the original message with audio in 9.954 seconds including upload.

Interpreter fallback and generated machine-state translations remain. These
measurements do not establish completion of the idiomatic Go rewrite.

## Sample worker sweep, 2026-10-23

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

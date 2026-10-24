# TODO

## Active: optimize playback preparation in direct Go

- [ ] Replace the remaining interpreted licensing hotspots with tested Go algorithms. Directly compiling obfuscated arithmetic is an intermediate optimization, not completion of this item.
- [ ] Measure complete request generation and licensed playback on Windows and Linux; preserve output equivalence and cancellation behavior.

## Complete idiomatic Go rewrite

- [x] Extract MT19937 seed, state update, and output tempering into an independent Go package; validate guarded caller adapters against the original operations. Offline SPC exercises state update and tempering; seed initialization still needs real-path coverage.
- [ ] Recover the remaining random-generator initialization and callers, then remove their temporary machine adapters.
- [x] Extract complete Montgomery squaring into independent Go limb arithmetic; verify raw results, interpreter boundary state, scheduling and randomized mathematical reference cases. Offline SPC covers 64-word operands.
- [x] Extract Montgomery multiplication into the same independent package; validate unreduced math/big results, caller state and scheduling. Complete offline SPC requests match the reference.
- [x] Extract the Montgomery word inverse using five Newton steps; validate mathematical results, caller state, aliasing and scheduling. Four replacements run per complete offline SPC request.
- [x] Extract modular input/output byte conversion, including the adjusted input path, partial words, padding and truncation. Compare accepted calls in complete offline SPC requests against original CPU/memory state; keep validation fixtures outside the client tree.
- [x] Replace the complete validated 2048-bit public-exponent caller with `math/big.Exp`, including byte output precedence and status copying. All four calls in 18 varied offline SPC requests use it and match the reference. Unsupported inputs and instruction observation retain the reference path.
- [ ] Recover remaining modular-arithmetic callers and remove their machine adapters after all supported paths have direct replacements.
- [ ] Replace the APK-derived instruction interpreter and translated routines with direct, idiomatic Go implementations across authentication, provisioning, licensing, and sample decryption, including the generated ALAC hot loop.
- [ ] Identify which static tables are still necessary and document their purpose; embedding translated instructions as Go arrays does not count as completing the rewrite.
- [ ] Remove `internal/apkgo` and its `.ir.gz` assets once all callers have replacements.
- [ ] Preserve the public client API and session behavior; validate correctness, end-to-end behavior, and performance on Windows and Linux with `CGO_ENABLED=0` before removing the existing implementation.

## Queued after Tunly validation and deployment

- [ ] Preserve validation evidence outside the client repository, then remove all client test files and testdata as requested.
- [ ] Audit Git history and staged content for account credentials and reusable session tokens.
- [ ] Consolidate related files and storage helpers, retaining private atomic saves and process ownership.
- [ ] Remove package header comments, update README and checks, and commit the cleanup.
- [ ] Notify the user through Telegram after deployment and again after client cleanup.

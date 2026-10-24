# AppleDL

Standalone Apple Music client library for Go. The high-level API is in
`github.com/AmarnathCJD/AppleDL/music`.

The client supports saved-session reuse, catalog search, song metadata and
advertised formats, and licensed ALAC acquisition and decryption. It builds with
`CGO_ENABLED=0`; it does not load DLLs/shared libraries or require Android, an
emulator, a JIT, or FFmpeg. Filesystem operations use Go's standard library.

## Quick start

Requires Go 1.25.3 or newer. Clone the repository, then run the example:

```sh
go run ./examples/client -query 'Blinding Lights'
```

The example uses `applemusic.dat` in the current directory. On first login, set
`APPLEMUSIC_USERNAME` and `APPLEMUSIC_PASSWORD` in your local environment. A valid
saved session takes precedence over supplied credentials. Never commit these
variables or session files.

```go
import (
    "context"
    "github.com/AmarnathCJD/AppleDL/music"
)

ctx := context.Background()
c, err := music.New(ctx, music.Config{
    SessionFile: "applemusic.dat",
    // Username and Password are optional when a saved session exists.
})
if err != nil {
    return err
}
defer c.Close() // Production callers should also check the returned save error.

page, err := c.Search(ctx, "Blinding Lights", music.SearchOptions{Limit: 5})
if err != nil {
    return err
}
if len(page.Songs) == 0 {
    return nil
}
song, err := c.GetSong(ctx, page.Songs[0].ID)
if err != nil {
    return err
}
// song.Formats includes codec, advertised bandwidth, a selection ID,
// and whether the client implements downloading that format.
result, err := c.DownloadAndDecryptSong(ctx, song.ID, "new-download-directory")
if err != nil {
    return err
}
_ = result.Path // Fragmented .m4a containing decrypted ALAC.
```

The complete runnable [example](examples/client/main.go) supports search, song
lookup, downloading, session reuse, worker counts and context export. For example:

```sh
go run ./examples/client -song 1499378607 -download ./download-1 -workers 16
```

Output directories must be new. The library preserves encrypted acquisition
files; failure may leave those files, but removes partial decrypted output.

## Sessions

`music.New(ctx, music.Config{})` checks the default session file, then existing
device state. If neither exists, it returns an empty client for a later import or
`Login`. Initialization validates saved credentials online with a fresh media
token; it does not silently fall back to a password when validation fails.

Session precedence:

1. `Config.Session` (an explicit exported string).
2. `Config.SessionFile` (default: `applemusic.dat`).
3. Existing commerce state in `Config.StateDir` (default: `.applemusic/device`).
4. Supplied username/password, when no saved commerce session exists.

```go
encoded, err := c.ExportSession() // URL-safe Base64; contains reusable credentials.
err = c.SaveSession("backup.dat")
err = c.ImportSession(ctx, encoded)
err = c.ImportSessionFromFile(ctx, "backup.dat")
err = c.Refresh(ctx)              // Saved credentials, no password exchange.
```

Import validates a staged copy before replacing the current session. A failed
validation preserves the previous session. An explicit username must match the
saved account. `Login` refreshes an already active matching account rather than
repeating a password exchange. `Close` saves the configured session file and is
idempotent. Check its error, especially during shutdown.

### Storage and portability

- Device, IdMS and commerce state use Go AES-256-GCM with a random 32-byte
  `state.key`. Copying the complete closed device directory preserves access on
  another supported OS. Copy all state files and the key together.
- Session exports and `.dat` files are **unencrypted bearer credentials**. Base64
  and the internal compressed checksum envelope are encodings, not encryption.
  A saved export is the easiest way to transfer a session between Windows and
  Linux. Do not print, publish or share it.
- The key is stored alongside encrypted state, so filesystem access controls
  protect both. This is not an OS credential vault. Go requests `0700` directories
  and `0600` files; on Windows, access is governed by the parent directory's ACLs.
- Existing legacy DPAPI files cannot be opened by this portable version. Keep
  their old directory intact; migrate using an export from the compatible build.
- Each client holds a `<session-file>.lock` directory, and each device holds a
  `device.lock` directory. Concurrent owners are rejected. After a crash, remove
  a leftover lock only after confirming the previous owner has exited. Locks are
  never stolen automatically. Use a local filesystem with reliable mkdir/rename.
- Saves write and sync a temporary file beside the destination, then call
  `os.Rename`. Replacement atomicity and power-loss durability depend on the
  operating system and filesystem; there are no direct platform API calls.

## API

| Method | Result |
| --- | --- |
| `New(ctx, Config)` | Reuses or creates a session; returns an empty client if no credentials exist |
| `Login(ctx, username, password)` | Logs in once, or refreshes an existing matching account |
| `Refresh(ctx)` | Obtains a fresh media token from saved commerce credentials |
| `ExportSession`, `SaveSession` | Exports all required reusable session state |
| `ImportSession`, `ImportSessionFromFile` | Validates and installs a saved session |
| `Search`, `NextSongs` | Paged catalog song metadata |
| `GetSong` | Song metadata plus advertised HLS formats |
| `DownloadAndDecryptSong` | Fresh ALAC acquisition, licenses and decrypted output |
| `Close` | Saves the configured session and releases resources |

Operations on one client are serialized; cancellation interrupts queued and
active work. ALAC sample processing uses independent workers, automatically
`min(16, GOMAXPROCS)`. Explicit worker counts are 1 through 64. A read receiving
HTTP 401 refreshes and retries once; passwords and license POSTs are not retried.

`DownloadOptions.FormatID` selects an advertised ALAC variant. The default picks
the highest advertised ALAC bandwidth. Exact bit depth, rate and channels are
returned after acquisition in `DownloadResult`.

### Offline context replay

Set `DownloadOptions{ExportContext: true}` to also save `encrypted-alac.m4a` and
its matching `license-context.amctx`. The context is private translated runtime
state bound to that exact ciphertext, not a raw AES key or Apple license response.

```go
r, err := music.DecryptBundle(ctx,
    "encrypted-alac.m4a", "license-context.amctx", "new-output.m4a", 16, nil)
```

Or use the standalone command:

```sh
go run ./cmd/amdecrypt -input encrypted-alac.m4a \
  -context license-context.amctx -output new-output.m4a
```

Replay verifies the bundle and ciphertext, restores matching contexts and runs
offline. Keep both inputs private. Output must be a new file.

## Implementation and limits

- Authentication, provisioning, license processing and sample execution all run
  in Go. The translated runtime in `internal/apkgo` executes build-time lowered
  APK operations. Its embedded `.ir.gz` files contain translated operations and
  static image data; they are required runtime assets, not native dependencies.
- Licensing uses compiled Go blocks for the measured hot paths, with an
  interpreter fallback for the remaining operations. Device initialization,
  authentication and parts of licensing still require that fallback. Removing
  it or its images before replacing those callers would break the client.
- MT19937 seeding, state update and output tempering are independent algorithms
  in `internal/mt19937`. Both recovered state-update callers use that algorithm,
  including the obfuscated table-generation caller. Temporary adapters connect
  them to existing callers; initialization and protocol orchestration still
  need replacement.
- The recovered byte mask and eight-byte word permutation are an independent
  slice transform in `internal/scramble`. Its table-generation caller uses it
  through a temporary adapter. It is a table representation transform, not a
  general-purpose cipher; the surrounding generator still needs replacement.
- Montgomery word inversion, multiplication, squaring and byte encoding are
  independent algorithms in `internal/montgomery`. The input conversion handles
  both plain and byte-adjusted data. The complete 2048-bit public-exponent
  operation now uses Go's `math/big.Exp`, including integer/byte output and status
  handling at the caller boundary. Its exponent comes from the caller; the
  adapter accepts only the validated public value. This variable-time function
  must not be used with secret exponents. Observed or unsupported calls retain
  the reference path. Protocol orchestration and other arithmetic callers still
  need replacement.
- The ALAC hot loop and instruction operations are generated translations. They
  preserve the analyzed behavior and have not been rewritten into a clean-room
  description of Apple's cryptographic algorithms. Public API, transport,
  storage, scheduling and orchestration are ordinary Go.
- The translated images originate from Apple Music Android 7.0.0 beta, build
  1606: `libCoreADI.so`, `libCoreFP.so`, `libCoreLSKD.so` and `libstoreapi.so`.
  `internal/playback/certificate.bin` is the observed public playback certificate,
  not a private key. These assets contain no user account or licensed context.
- ALAC is the implemented download/decryption codec. Other advertised formats
  are listed but marked unsupported. Account entitlement and server availability
  still apply. Interactive two-factor authentication/account challenges are not
  implemented. Existing valid sessions avoid repeating login.
- Playback currently requires one initialization map, a continuous sample
  timeline and one Apple key per segment. Alternative DRM declarations alongside
  the Apple declaration are supported; ambiguous key versions are rejected.
- Windows amd64 and Linux amd64 are the validation targets. Other Go targets may
  compile but need runtime validation. No guarantee is made about future Apple
  protocol or service changes.

See [performance measurements](docs/PERFORMANCE.md) for worker-count tradeoffs.

## Checks

The ordinary suite uses synthetic fixtures and performs no live account login.
Optional provisioned-device tests require explicitly supplied local state.

```sh
CGO_ENABLED=0 go test ./... -count=1
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build ./...
```

Validated on Windows amd64 and Debian/WSL Linux amd64 with CGO disabled. Both
platforms passed tests, vet and build. A Windows-exported session was reused on
Linux for search, format lookup, fresh acquisition, licensing and ALAC decryption.
Outputs passed strict full-file FFmpeg decoding, and replay of the same exported
bundle produced byte-identical output on both platforms.

This WSL installation forwards localhost through Windows. Its offline TLS tests
ran in a temporary Linux network namespace with loopback enabled; live service
tests used the normal network. No global networking changes were required.

On Windows, `./check.ps1` runs the same checks with its cache under the repository.
FFmpeg is useful for independent full-output decode validation; the library does
not invoke it. Research artifacts, binaries, credentials, sessions and downloaded
media are kept outside this repository.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

PgpCore is a .NET class library (NuGet package) wrapping BouncyCastle.Cryptography to provide PGP operations: encrypt, decrypt, sign, clear-sign, detached-sign, verify, inspect, and key generation. It multi-targets `netstandard2.0` and `net10.0`; the test project targets `net10.0`.

## Commands

```powershell
# Build (use Debug — Release requires the assembly-signing PgpCoreKey.pfx used by CI)
dotnet build

# Run all tests except gpg interop (what Windows CI runs)
dotnet test PgpCore.Tests/PgpCore.Tests.csproj --filter "Category!=Interop"

# Run a single test / test class
dotnet test PgpCore.Tests/PgpCore.Tests.csproj --filter "FullyQualifiedName~ClearSignAsync_SignEmptyMessage"

# Run gpg interop tests (require gpg on PATH; auto-skip via GpgFactAttribute when absent)
dotnet test PgpCore.Tests/PgpCore.Tests.csproj --filter "Category=Interop"
```

The full suite takes ~2 minutes. Test collections run sequentially (`parallelizeTestCollections: false` in xunit.runner.json) because tests share temp key/content files on disk.

CI (`.github/workflows/`): Windows job builds and runs non-interop tests with coverage; a separate Ubuntu job runs the interop tests (MSYS gpg on the Windows runner mishandles `--homedir` paths); SonarCloud analysis consumes the coverage artifact.

## Architecture

### One class, many partials

The entire public API is a single `PGP` partial class split by operation and sync/async across `PgpCore/PGP.<Operation><Sync|Async>.cs` files (e.g. `PGP.EncryptAsync.cs`, `PGP.VerifySync.cs`). `PGP.cs` is the hub: constructor, algorithm-default properties (`SymmetricKeyAlgorithm`, `HashAlgorithmTag`, `CompressionAlgorithm`, etc.), and all shared private helpers (`OutputEncryptedAsync`, `OutputClearSignedAsync`, `ChainEncryptedOut`/`ChainCompressedOut`/`ChainLiteralOut`, canonical-line helpers). The interface `IPGP` in `Abstractions/` mirrors this exactly with one `IPGP.<Operation><Sync|Async>.cs` partial per file — adding a public method means touching both.

**Sync methods are thin wrappers** that call the async implementation via `.GetAwaiter().GetResult()`. Implement logic once, in the async partial; never duplicate it in the sync file.

Each operation typically exposes File/Stream/String overloads, where FileInfo and string overloads funnel into the Stream implementation.

### Key material

`Models/EncryptionKeys.cs` encapsulates all key material (public/private/symmetric, many constructor overloads for string/FileInfo/Stream sources; `EncryptionKeysBuilder` provides a fluent alternative). It is passed to the `PGP` constructor and consumed via `IEncryptionKeys` — sign operations use `SigningSecretKey`/`SigningPrivateKey`, verify operations use `VerificationKeys` (including subkeys), encrypt uses `EncryptKeys`.

### Error model

Operations throw typed exceptions from `Exceptions/`, all deriving from `PgpCoreException` (which derives from `System.Exception`, not BouncyCastle's `PgpException` — a v8 breaking change). Prefer these over generic exceptions for new failure paths.

### Clear-sign canonicalization (fragile area)

Clear-sign/verify-clear implement RFC 4880 §7.1 canonical text rules by hand: trailing whitespace per line is excluded from the hash, lines are joined with CRLF, and the final line's separator is not hashed. The sign side lives in `OutputClearSignedAsync` (PGP.cs), the verify side in `VerifyClearAsync` (PGP.VerifyAsync.cs) with the `ReadInputLine`/`ProcessLine` helpers. Edge cases (consecutive newlines, trailing newlines, empty content) have all broken this in the past — regression tests exist in `PgpCore.Tests/UnitTests/Sign/SignAsync.String.cs` and any change here must keep output byte-compatible with what gpg produces (guarded by the interop tests).

### gpg interop tests

`PgpCore.Tests/UnitTests/Interop/GpgInteropTests.cs` shells out to real GnuPG (`GpgRunner` handles gpg 1.4 vs 2.x differences such as `--pinentry-mode loopback`). Use `[GpgFact]` (optionally with a minimum version, e.g. `[GpgFact("2.1")]`) and `[Trait("Category", "Interop")]` for new interop tests. These are the source of truth for wire-format compatibility.

### Test conventions

Tests use xunit + FluentAssertions. `TestFactory` arranges per-test temp directories with keys and content: `testFactory.ArrangeAsync(KeyType.Known, FileType.Known)` then expose `PrivateKey`/`PublicKey`/`Password`/`Content` and `*FileInfo` properties; call `testFactory.Teardown()` at the end. `KeyType` values: `Generated` (fresh key, slow), `Known`, `KnownGpg` (checked-in fixtures), `Symmetric`. Round-trip tests conventionally run as `[Theory]` across all four key types. Tests are organized under `UnitTests/<Operation>/<Operation><Sync|Async>.<File|Stream|String>.cs`.

## Conventions

- Library code must use `ConfigureAwait(false)` on every await (CA2007 is elevated to warning via .editorconfig).
- `PgpCore/` source uses tabs; the test project uses 4-space indentation — match the file you're editing.
- Version lives in `PgpCore.csproj` (`Version`/`AssemblyVersion`/`FileVersion` plus `PackageReleaseNotes`); v8 changed crypto defaults and removed members — the README's "Upgrading to v8.0" section documents the migration and should stay accurate if defaults change again.

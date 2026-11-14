# CI/CD

Workflows live in `.github/workflows/`. Every third-party action is pinned to a full commit SHA
(Dependabot keeps the pins current). Each workflow defaults to `permissions: contents: read`;
only the release `publish` job gets `contents: write`.

## ci.yml (every push / pull request)

| Job | Runner | What it does |
|---|---|---|
| Rust core | ubuntu, macos, windows | `cargo fmt --check` (Linux), `cargo clippy -D warnings`, `cargo test --locked` |
| Loopback latency benchmark | ubuntu | `annex-bench`, uploads `bench-results/loopback.{json,csv}`; fails if p95 > 25 ms |
| macOS app | macos-latest | `xcodebuild test`, then an unsigned universal `.dmg` artifact |
| Windows app | windows-latest | builds `annex_ffi.dll`, `dotnet test` interop tests against it, builds the WinUI app, packages an unsigned x64 installer artifact |
| Supply chain | ubuntu | `cargo deny check` (advisories, licenses, bans, sources) + `cargo audit` |

`codeql.yml` analyzes Rust, C#, Swift and the workflows themselves (on push to main, PRs, weekly).
`dependabot.yml` covers cargo, NuGet and GitHub Actions (Swift has no packages yet).
Caches: cargo registry + `core/target`, NuGet (via setup-dotnet + lock files), SwiftPM.
Superseded runs are cancelled by a concurrency group.

The Windows virtual display driver job (WDK build) is added with the driver in M4.

**linux-app** (ubuntu-22.04 and ubuntu-22.04-arm, the oldest supported system): `cargo fmt
--check`, clippy, tests, then `scripts/package-linux.sh`; installs the `.deb` and runs
`annex --version`; uploads the `.deb`, `.rpm` and `.tar.gz`. armhf and riscv64 build from source
for now; see [LINUX.md](LINUX.md#6-releases).

## release.yml

Triggers: tag `vX.Y.Z` (or `vX.Y.Z-rc.N`), or **workflow_dispatch** with `dry_run` (default
true), which builds and uploads every artifact as a workflow artifact without creating a release.

1. **version**: version comes from the tag (or the input / `core/Cargo.toml` for dry runs).
2. **macos** (environment `release`): selects the pinned Xcode (`.xcode-version`), stamps the
   version into the Rust core (`scripts/stamp-version.sh`), imports the Developer ID cert into
   a temporary keychain, builds a **universal** app, signs it with hardened runtime, notarizes
   with `notarytool` (App Store Connect API key), staples, and packages a signed `.dmg`.
3. **windows** (environment `release`, x64 + arm64): builds the core and the self-contained
   WinUI app, signs binaries with `signtool` if a certificate is configured, packages
   `Annex-Setup-<version>-<arch>.exe` (Inno Setup, preinstalled on the runners) and signs it.
4. **linux** (x86_64 + arm64, Ubuntu 22.04): stamps the version, runs
   `scripts/package-linux.sh`, installs the `.deb` as a check, and uploads
   `Annex-<version>-linux-<arch>.{deb,rpm,tar.gz}`. Not signed beyond `SHA256SUMS.txt`.
5. **publish** (`contents: write`): SHA-256 sums (`SHA256SUMS.txt`), SPDX SBOMs (syft),
   and `gh release create --draft --generate-notes`. **You publish the draft manually.**

### Required secrets (environment `release`, with required reviewers)

| Secret | Used for |
|---|---|
| `MACOS_CERT_P12_BASE64` | Developer ID Application certificate + key, base64 of the .p12 |
| `MACOS_CERT_PASSWORD` | Password of that .p12 |
| `APPLE_TEAM_ID` | Your 10-character team ID |
| `ASC_API_KEY_ID`, `ASC_API_ISSUER_ID`, `ASC_API_KEY_P8` | App Store Connect API key for notarization (contents of the .p8) |
| `WIN_CERT_PFX_BASE64`, `WIN_CERT_PASSWORD` | Windows code-signing certificate (OV/EV) as base64 .pfx |

All are optional: without them the jobs still succeed and produce ad-hoc signed (macOS) or
unsigned (Windows) builds, and print a warning. Secrets are only written to `$RUNNER_TEMP` and
deleted in `always()` steps. Nothing is echoed; the signing identity is masked.

To set up the environment: Settings → Environments → New environment `release` → add
required reviewers → add the secrets above.

### Cutting a release

1. Bump `version` in `core/Cargo.toml` (workspace) and commit. Optional: the workflow stamps
   the tag version anyway.
2. `git tag v0.2.0 && git push origin v0.2.0`
3. Approve the `release` environment deployment in the Actions run.
4. Review the draft release (artifacts, checksums, SBOMs, notes), then **Publish**.

### Rotating certificates

- **Apple**: create a new Developer ID Application certificate in your developer account,
  export it with its key as .p12, base64 it (`base64 -i cert.p12 | pbcopy`), and replace
  `MACOS_CERT_P12_BASE64` / `MACOS_CERT_PASSWORD`. Rotate the App Store Connect API key under
  Users and Access → Integrations, then replace the three `ASC_*` secrets and revoke the old key.
- **Windows**: replace `WIN_CERT_PFX_BASE64` / `WIN_CERT_PASSWORD`. If you move to Azure
  Trusted Signing, swap the "Prepare code signing" step for the Trusted Signing action with
  OIDC (no long-lived secret).
- Old signatures stay valid because they are timestamped.

## Reproducibility

Pinned: Rust toolchain (`rust-toolchain.toml`), `Cargo.lock` (`--locked` everywhere), Xcode
(`.xcode-version`, release), .NET SDK (`global.json`), NuGet lock files, action
SHAs. `global.json` stays at the repository root: `dotnet` looks for it from the folder it runs
in, and CI runs it from the root, so anywhere deeper it is skipped and the runner's newest SDK
changes the NuGet lock files' implicit packages (`Microsoft.NET.ILLink.Tasks`). Rebuilding a tag reproduces the same inputs. Signed and notarized binaries are not
byte-for-byte identical across builds (signatures and timestamps differ), and we don't claim
they are.

## What hosted runners cannot verify

Hosted runners have no display, GPU encoder or second machine, and can't load drivers.
These stay manual (see `docs/TESTING.md`) or need a self-hosted runner:

- Real screen capture (Screen Recording permission, ScreenCaptureKit / Windows Graphics Capture)
- Hardware encoders (the macOS test falls back to software if no hardware encoder exists)
- The Windows viewer window (D3D11 video processor, Media Foundation decode)
- mDNS discovery between machines, Wi-Fi / wired latency
- Virtual display creation (M4) and driver loading
- Installer UI flows (install to another drive, uninstall cleanup)

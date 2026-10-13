# Contributing

Thanks for your interest. Bug reports, fixes and focused features are welcome.

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep changes small and self-contained. One topic per pull request.
3. Every behavior change comes with a test. Run before you push:
   ```sh
   cargo fmt --check || true   # formatting is not enforced yet, but keep diffs tidy
   cargo test --all-targets
   (cd crates/netmesh-client && cargo test)
   ```
4. Security-sensitive code (signature checks, admission, MACs, replay windows, bind checks) needs a test that a
   stranger, a forged message or a replay is refused.
5. Do not change wire formats (`net.mesh/*` protocol tags) without bumping the version in the tag.
6. Never commit keys, secrets, state files or captured traffic.

By contributing you agree that your contributions are licensed under the Apache License 2.0.

Security issues: please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

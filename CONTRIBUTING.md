# Contributing

Thanks for helping. A few rules keep a security tool trustworthy:

1. **`npm test` must pass.** It runs every `test/*.sh` suite against a real local server.
   You need Node ≥ 20, git ≥ 2.40, bash ≥ 4 and curl.
2. **Security fixes need an adversarial test that fails before the fix.** Follow the style in
   `test/e2e.sh`: `expect_reject` asserts the specific error message, so an attack can't
   "pass" by failing for an unrelated reason.
3. **Open an issue before touching crypto, the envelope format, the proxy or the pre-receive
   hook.** Those are the security boundary; design first.
4. **No runtime dependencies.** Node's standard library and git only. This is a project
   principle: you should be able to read everything you're trusting.
5. Update THREAT_MODEL.md when you add or change a defense, and README.md when you change
   user-facing behavior.

Found a vulnerability? Don't open an issue; see [SECURITY.md](SECURITY.md).

Responses are best effort. This is a young project.

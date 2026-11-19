# Contributing

1. `make verify` must pass: fmt-check, clippy with warnings denied, the
   tests, the smoke test.
2. Fixtures are synthetic. A new answer shape becomes a file in
   `tests/fixtures/salve/` with the real answer's keys and types and
   invented values from `tests/fixtures/README.md`, never a copy of a real
   answer.
3. No personal data anywhere: code, docs, commit messages, pull requests,
   issues. `tests/no_personal_data.rs` enforces the shapes; review the rest.
4. A new query comes with its entry in `docs/api.md`, a fixture, and the
   stub's answer in `tests/common/mod.rs`. A mutation needs a change to the
   read-only rule in `AGENTS.md` first.
5. A change to `src/srp.rs` keeps `tests/srp_vector.rs` passing; the vector
   comes from AWS's own client and is never regenerated from salve.
6. Squash merges only, with an approval and green CI.

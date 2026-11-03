# Contributing

Thanks for your interest! otpkit is intentionally small — correctness and clarity matter more than features.

## Setup

```sh
npm ci
npm run check      # typecheck + lint + format check + tests
npm run coverage   # the suite maintains 100% line/branch coverage
```

## Guidelines

- **Zero runtime dependencies** is a core promise. Dev dependencies are fine.
- Behaviour that maps to an RFC should be pinned by that RFC's published test vectors.
- Add a test for every bug fix and feature, and a `CHANGELOG.md` entry under **Unreleased**.
- Invalid configuration throws `RangeError`; a bad _token_ never throws — it just fails verification.
- Run `npm run format` before committing.

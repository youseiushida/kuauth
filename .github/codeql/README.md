# CodeQL custom queries for kuauth

This directory holds the bespoke static-analysis queries that protect
credential surfaces specific to `kuauth`. They run in the `CodeQL`
workflow (`.github/workflows/codeql.yml`) alongside GitHub's
`security-extended` Python suite.

## Layout

The shared models live in a separate library pack so that the query
pack imports them via the dependency graph rather than as sibling
files. This avoids the "references a local library, not the named
module" warning that CodeQL emits when query packs reach across to
helper `.qll` files.

```
.github/codeql/
  .codeqlmanifest.json       # workspace manifest (3 packs)
  codeql-config.yml          # which queries run, which paths to scan
  README.md                  # (this file)
  lib/
    qlpack.yml               # library pack — kuauth/credential-leak-lib
    KuauthSources.qll        # shared model: credential sources
    KuauthSinks.qll          # shared model: leak sinks
    KuauthAllowedHosts.qll   # shared model: legitimate IdP submitters
  queries/
    qlpack.yml               # query pack — kuauth/credential-leak-queries
    codeql-suites/
      credential-leak.qls    # suite that selects the local queries
    CredLeak-Logging.ql      # query: creds -> logging
    CredLeak-Exception.ql    # query: creds -> exception messages
    CredLeak-ReprStr.ql      # query: creds -> __repr__ / __str__
    CredLeak-Disk.ql         # query: creds -> file/serialization writes
    CredLeak-UnknownHttp.ql  # query: creds -> non-IdP HTTP egress
    tests/
      qlpack.yml             # test pack — depends on both lib + queries
      <QueryName>/
        test.py              # extraction input
        <QueryName>.qlref    # references the query under test
        <QueryName>.expected # expected output (regenerated via --learn)
```

## Sources, sinks, sanitizers

Sources (`lib/KuauthSources.qll`) are credential-bearing values:

- `KyotoUAuth.password` (property) and `_password` (attribute)
- `KyotoUAuth._totp_secret`
- `KyotoUAuth._onetime_password`
- Return value of `KyotoUAuth._resolve_otp()`
- Return value of invoking `KyotoUAuth._otp_callback`

`username` is not a source — it is shared with the IdP in URL-resolvable
form (EPPN) and treating it as taint dilutes precision without adding
protection. `__init__` parameters are not modeled directly because every
realistic flow into a sink goes through the post-construction attribute
read (`self._password` etc.), which the attribute source already
covers.

Sinks (`lib/KuauthSinks.qll`):

- Logging: `logging.*`, `Logger.*` (typed via API graphs), `print`,
  `warnings.warn`, `sys.stdout/stderr.write`, `traceback.print_*`. For
  `logger.<level>(msg, *args)` every positional argument is a sink
  (args 1+ are `%`-substitutions that get rendered into the log line).
- Exception: argument of `raise X(...)`
- ReprStr: return value of `__repr__` / `__str__`
- Disk: `open().write`, `Path.write_text/write_bytes`, `json.dump(s)`,
  `pickle.dump(s)`, `csv.writer.writerow(s)`, `csv.DictWriter.writerow(s)`
- HTTP: any `.get/post/put/patch/delete/request/send/stream(...)` method
  call OR module-level `httpx.<method>(...)`. We don't type-filter the
  receiver because httpx is third-party and CodeQL's API graph cannot
  reliably follow `KyotoUAuth._http = httpx.Client()` → `_SPService.http`
  property → `self.http.post(...)` end to end. Method-name + httpx-shape
  argument matching (positional URL or `params`/`data`/`json`/`headers`/
  `content` keyword) is specific enough that non-HTTP `.get()` /
  `.append()` collisions don't reach the sink.

Sanitizer (`lib/KuauthAllowedHosts.qll`): the four legitimate auth-form
submitters

- `_submit_simplesaml_password`
- `_submit_simplesaml_otp`
- `_submit_shib_idp_login`
- `PandA._submit_cas_login` (class-pinned)

Any HTTP egress whose enclosing function matches the allowlist is
treated as a sanitization barrier in `CredLeak-UnknownHttp`. Adding a
fifth IdP submitter is intentionally a code change here — silent
allowlist drift is a worse failure mode than a noisy CI alert for a
credential-handling library.

## Running locally

Install the CodeQL CLI
(<https://github.com/github/codeql-cli-binaries/releases>) and ensure
`codeql` is on `PATH`.

```bash
# Resolve dependencies for all three local packs.
codeql pack install .github/codeql/lib
codeql pack install .github/codeql/queries
codeql pack install .github/codeql/queries/tests

# Build a database from the kuauth source tree.
codeql database create --language=python --source-root=. ./codeql-db

# Run the local pack against the database.
codeql database analyze ./codeql-db \
  --format=sarif-latest \
  --output=results.sarif \
  .github/codeql/queries
```

## Updating expected test output

The `.expected` files in `tests/<QueryName>/` are regenerated whenever a
query's output format changes:

```bash
# From the repo root:
codeql test run --learn .github/codeql/queries/tests/

# Then commit the updated .expected files.
codeql test run .github/codeql/queries/tests/   # verifies they match
```

The first time you run `--learn`, CodeQL writes `.expected` files
containing the actual query output. Inspect them and confirm that
positive cases (functions named `leak_*`) appear and negative cases
(functions named `safe_*`) do not before committing.

## Adding a new query

1. Add `<QueryName>.ql` and `<QueryName>.qhelp` under `queries/`. If it
   needs a new shared source/sink/sanitizer, add it to one of the
   `lib/*.qll` files first.
2. Add a `tests/<QueryName>/` directory with `test.py` (positive +
   negative cases) and `<QueryName>.qlref`.
3. Run `codeql test run --learn .github/codeql/queries/tests/` to
   produce the `.expected` file.
4. Commit all four files together.

## Surface invariant test

The QL test fixtures use synthetic stand-ins for `KyotoUAuth` so they
can be extracted by `codeql test run` without pulling in the whole
`src/kuauth` tree. A rename like `_password` → `_pw` in
`src/kuauth/auth.py` would silently break the queries while the QL
tests stayed green.

To close that gap, `tests/unit/test_codeql_query_surface.py` pins the
exact attribute and method names that the queries match against. If a
rename in `src/` breaks those names, the pytest run fails first, so
you cannot land the rename without also updating `KuauthSources.qll` /
`KuauthAllowedHosts.qll` and regenerating the QL baselines in the same
change.

Runs as part of the standard `uv run pytest tests/unit -q`. No CodeQL
CLI required.

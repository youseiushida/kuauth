# Test fixtures

Sanitized HTML/JSON snippets that mirror the real SP/IdP responses for use in
`tests/replay/`. These are hand-crafted to match the structural elements
our parsers need; bodies were not available in the captured HARs (Chrome
exports omit them by default).

No real credentials, session IDs, CSRF tokens, SAMLResponse payloads, or
personally-identifying identifiers appear in these files. All placeholder
values begin with `TEST_` or use the reserved `example.test` domain.

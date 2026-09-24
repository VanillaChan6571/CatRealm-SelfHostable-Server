# Server regression tests

Run `npm test` from the self-hostable server directory with dependencies installed.
The suite uses Node's built-in test runner, isolated SQLite databases, temporary
upload fixtures, and mocked ACME requests/timers. It does not open the production
database or request real certificates. It covers attachment path containment,
live permission changes, thread authorization, reply privacy, and TLS recovery.

The security recheck adds shared-attachment, scheduled-source, and unreadable-source
coverage. Expiry cleanup preserves attachments and thumbnails referenced by
surviving messages while removing unreferenced batch uploads. Tests delete only
synthetic files in newly created temporary directories; production uploads are untouched.

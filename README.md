# CI test fixtures

This tag exists only to host historical MinIO binaries as release assets for
the functional tests in this repository. MinIO has taken its download site
(dl.min.io) offline, so the tests that need an old server or client to
exercise upgrade and compatibility paths fetch them from the release attached
to this tag instead:

- minio.linux-amd64.RELEASE.2020-10-28T08-16-50Z  (buildscripts/rewrite-old-new.sh)
- minio.linux-amd64.RELEASE.2024-03-26T22-10-45Z  (buildscripts/minio-iam-ldap-upgrade-import-test.sh)
- mc.linux-amd64.RELEASE.2021-03-12T03-36-59Z     (docs/bucket/replication/setup_3site_replication.sh)

The assets are byte-for-byte copies of the binaries MinIO published on the
corresponding GitHub releases. Where MinIO published a .sha256sum alongside
the binary (the 2024 server and the 2021 client) the copies were verified
against it before upload; SHA256SUMS records the digests of all three and the
scripts verify against them at download time.

The tag is deliberately on an orphan commit so it is never an ancestor of
master and cannot be mistaken for a release by tooling that walks tag history.

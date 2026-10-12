<!--
  ~ Copyright (c) 2023-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Making a release

A tag releases `personal-agent-protocol` to PyPI and
`@datalayer/personal-agent-protocol` to npm with no stored publishing tokens.
Each registry trusts `.github/workflows/release.yaml` through OIDC. The Python
version lives in `personal_agent_protocol/__version__.py`, which Hatch reads;
the TypeScript version lives in the root `package.json`. They must match the
tag.

## Steps

1. Bump both package versions on a branch and open a pull request. Update the
   matching runtime plugin manifests.

1. Merge, then tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

1. The `Release` workflow checks that the tag names both versions, builds and
   tests the Python and TypeScript packages, publishes versions not already on
   their registries, and creates a GitHub release with generated notes.

## Trusted publishing

- PyPI project `personal-agent-protocol`: owner `datalayer`, repository
  `personal-agent-protocol`, workflow `release.yaml`, environment `pypi`.
- npm package `@datalayer/personal-agent-protocol`: repository
  `datalayer/personal-agent-protocol`, workflow `release.yaml`, environment
  `npm`, with publish permission.

Registry configuration must match the repository, workflow filename, and
environment exactly. Renaming any of them requires updating the trusted
publisher configuration.

## Signatures

PyPI distributions are published with PEP 740 attestations
(`attestations: true`) and the npm package with a provenance statement
(`--provenance`); both need the job's `id-token: write`. After a release,
check them:

- PyPI: the release's files list a provenance attestation
  (`https://pypi.org/integrity/personal-agent-protocol/<version>/<file>/provenance`).
- npm: `npm view @datalayer/personal-agent-protocol@<version> dist.attestations`
  names the provenance predicate, and `npm audit signatures` verifies it.

## Before tagging

Bump `personal_agent_protocol/__version__.py`, `package.json`, the plugin
manifests' versions (`personal_agent_protocol/reactor.py`,
`personal_agent_protocol/company/__init__.py`, `src/reactor.ts`,
`src/company/index.ts`), the [compatibility](docs/docs/releases/compatibility.mdx)
and [support](docs/docs/releases/support.mdx) pages, a migration section for a
breaking release, and the changelog; regenerate the conformance report. The
tests fail when any of them is stale.

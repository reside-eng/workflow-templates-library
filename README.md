# workflow-templates-library
Templates for Side librairies github actions

## Table of Contents

- [verify_library](#verify_library)
- [release_library](#release_library)

## verify_library

### Inputs

| Input | Type | Default | Required |
| ---------------------- | ------------------------------------------------ | --------- | -------------------- |
| NODE_VERSION | string | 18.x | `false` |
| TIMEOUT | number | 15 | `false` |
| ENABLE_TYPES_CHECK | boolean | false | `false` |
| ENABLE_FORMAT_CHECK | boolean | false | `false` |
| ENABLE_SIZE_LIMIT_CHECK | boolean | false | `false` |
| ENABLE_VISUAL_TESTING | boolean | false | `false` |
| IS_MONOREPO | boolean | false | `false` |
| ENABLE_SLACK_NOTIFICATION | boolean | true | `false` |
| SLACK_NOTIFICATION_SECRET | string | SLACK_WEBHOOK_PLATFORM_NONPROD | `false` |

### Secrets

| Secret | Required |
| ---------------------- | ---------------------- |
| NPM_READ_TOKEN | `true` |
| LIBRARY_CI_SERVICE_ACCOUNT | `true` |
| PERCY_TOKEN | `false` (required when `ENABLE_VISUAL_TESTING=true`) |

## release_library

### Inputs

| Input | Type | Default | Required |
| ---------------------- | ------------------------------------------------ | --------- | -------------------- |
| NODE_VERSION | string | 18.x | `false` |
| TIMEOUT | number | 15 | `false` |
| ENABLE_TYPES_CHECK | boolean | false | `false` |
| ENABLE_FORMAT_CHECK | boolean | false | `false` |
| ENABLE_SIZE_LIMIT_CHECK | boolean | false | `false` |
| ENABLE_VISUAL_TESTING | boolean | false | `false` |
| IS_MONOREPO | boolean | false | `false` |
| ENABLE_SLACK_NOTIFICATION | boolean | true | `false` |
| SLACK_NOTIFICATION_SECRET | string | SLACK_WEBHOOK_PLATFORM_NONPROD | `false` |
| ENABLE_NPM_TOKEN_FALLBACK | boolean | true | `false` |

### Secrets

| Secret | Required |
| ---------------------- | ---------------------- |
| NPM_PUBLISH_TOKEN | `false` (fallback while `ENABLE_NPM_TOKEN_FALLBACK=true`, see below) |
| NPM_READ_TOKEN | `true` |
| LIBRARY_CI_SERVICE_ACCOUNT | `true` |
| SIDE_CI_APPLICATION_ID | `false` (required when `IS_MONOREPO=true`) |
| SIDE_CI_APPLICATION_PRIVATE_KEY | `false` (required when `IS_MONOREPO=true`) |
| PERCY_TOKEN | `false` (required when `ENABLE_VISUAL_TESTING=true`) |

### Graduation notes (Lerna monorepos only)

| Input | Type | Default | Required |
| ---------------------- | ------------------------------------------------ | --------- | -------------------- |
| ENABLE_GRADUATION_NOTES | boolean | true | `false` |
| GRADUATION_NOTES_SPEC | string | @side/graduation-notes@^1 | `false` |

When a prerelease line graduates, `lerna publish --conventional-graduate` resolves
conventional-changelog's `from` to the last **prerelease** tag of the package. The commit range is
empty, so the GitHub Release body is just
`**Note:** Version bump only for package <pkg>` — every itemised change of the prerelease line is
missing from the stable release (`packages/<pkg>/CHANGELOG.md` still has them; only the release body
is empty).

After `lerna publish` on `main`, this workflow aggregates the package's own prerelease releases into
the stable release **body** via
[`.github/actions/graduation-notes`](.github/actions/graduation-notes). It patches release bodies
only — no commit, no push, no bypass actor — is idempotent, and re-reads every release it patched to
assert the notes actually published.

The aggregation engine (`@side/graduation-notes`) is installed at release time. **Until it is
published the step warns and skips**, leaving releases exactly as Lerna produced them. Set
`ENABLE_GRADUATION_NOTES: false` to opt out entirely.

### npm Trusted Publishing (OIDC)

Packages are published with [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/):
`npm publish` (semantic-release) and `lerna publish` (Lerna >= 9) exchange the job's GitHub OIDC token
for a short-lived npm token, so no long-lived publish token is needed. The `release` job declares
`id-token: write` itself; callers keep `secrets: inherit` and need no change.

Per package, a trusted publisher must exist on npmjs.com pointing at the **calling** repository and the
**calling** workflow file (the file in the library repo that `uses:` this workflow, e.g. `release.yml`),
with no environment. One-off setup by a maintainer with 2FA (npm >= 11.15):

```bash
npm trust github @side/<package> --repo reside-eng/<repo> --file release.yml --allow-publish
```

`--allow-publish` matters: configurations created since 2026-09-03 only allow *staged* publishing by
default, and the registry then accepts `npm publish` without the version ever going live. Check with
`npm trust list @side/<package>` that the configuration allows publish. The workflow fails the release
when a version it published is not visible on the registry within two minutes (the `Verify ... live on
npm` steps), which also logs the publisher: `GitHub Actions <npm-oidc-no-reply@github.com>` = OIDC.

Until every package of a repo has a trusted publisher, leave `ENABLE_NPM_TOKEN_FALLBACK` at `true`:
OIDC is attempted first and `NPM_PUBLISH_TOKEN` is used only when the registry refuses the exchange.
Then set the input to `false`; the job still needs `NPM_READ_TOKEN` to install private `@side/*`
dependencies.

Constraints: GitHub-hosted runners only (`ubuntu-latest`), npm >= 11.5.1 (installed by the job when
the Node line ships an older npm), and the package's `repository.url` must match the GitHub repo.
A brand-new package has to be published once with a token before a trusted publisher can be added.


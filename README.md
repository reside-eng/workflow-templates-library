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

### Secrets

| Secret | Required |
| ---------------------- | ---------------------- |
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

Each package needs a trusted publisher on npmjs.com pointing at the **calling** repository and the
**calling** workflow file (the file in the library repo that `uses:` this workflow, e.g. `release.yml`),
with no environment. `npm view @side/<package>@<version> _npmUser` shows who published a version:
`GitHub Actions <npm-oidc-no-reply@github.com>` for CI, the npm user name for a manual publish.

#### First release of a new package

The release can only publish a package that already exists on npm and has a trusted publisher. A new
package needs the steps below once, before its first release: before merging the PR that adds it to a
Lerna monorepo, or before enabling the release workflow of a new repository. Use an npm account with 2FA
and write access to `@side`; `npm trust` needs npm >= 11.15, hence `npx`.

1. Build it the way CI does: `yarn build` in a single-package repository,
   `yarn lerna run build --scope @side/<name>` in a monorepo.
1. From the directory that gets published (`packages/<name>` in a monorepo, otherwise the `pkgRoot` of
   `release.config.js` when set, otherwise the repository root), publish the current version as a
   placeholder:

   ```bash
   npx -y npm@11 publish --access restricted
   ```

1. Attach the trusted publisher. Keep `--allow-publish`: without it, npm only stages the publishes and
   they never go live.

   ```bash
   npx -y npm@11 trust github @side/<name> --repo reside-eng/<repo> --file release.yml --allow-publish
   ```

1. Check that `npx -y npm@11 trust list @side/<name>` lists `publish` in `permissions`.

The next release then publishes the real version through OIDC. Without these steps that release fails
with `E403` after it has already pushed its git tags.

The job still needs `NPM_READ_TOKEN`: it installs the private `@side/*` dependencies, and trusted
publishing covers `npm publish` only.

Constraints: GitHub-hosted runners only (`ubuntu-latest`), npm >= 11.5.1 (installed by the job when
the Node line ships an older npm), and the package's `repository.url` must match the GitHub repo.


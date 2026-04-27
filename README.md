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
| NPM_PUBLISH_TOKEN | `true` |
| NPM_READ_TOKEN | `true` |
| LIBRARY_CI_SERVICE_ACCOUNT | `true` |
| SIDE_CI_APPLICATION_ID | `false` (required when `IS_MONOREPO=true`) |
| SIDE_CI_APPLICATION_PRIVATE_KEY | `false` (required when `IS_MONOREPO=true`) |
| PERCY_TOKEN | `false` (required when `ENABLE_VISUAL_TESTING=true`) |


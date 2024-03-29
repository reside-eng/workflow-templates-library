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
| PACKAGE_MANAGER | string | yarn-berry | `false` |
| ENABLE_TYPES_CHECK | boolean | false | `false` |
| ENABLE_FORMAT_CHECK | boolean | false | `false` |
| ENABLE_SIZE_LIMIT_CHECK | boolean | false | `false` |
| ENABLE_VISUAL_TESTING | boolean | false | `false` |
| IS_MONOREPO | boolean | false | `false` |
| ENABLE_SLACK_NOTIFICATION | boolean | true | `false` |
| SLACK_NOTIFICATION_SECRET | string | SLACK_WEBHOOK_CORE_NON_PROD | `false` |

### Secrets

| Secret | Required |
| ---------------------- | ---------------------- |
| NPM_READ_TOKEN | `true` |
| SLACK_WEBHOOK_CORE_NON_PROD | `false` |
| SLACK_WEBHOOK_PLATFORM_PROD | `false` |
| SLACK_WEBHOOK_PLATFORM_SERVICES_NONPROD | `false` |
| SLACK_WEBHOOK_UI_WG | `false` |
| CI_SERVICE_ACCOUNT | `false` |


## verify_library

### Inputs

| Input | Type | Default | Required |
| ---------------------- | ------------------------------------------------ | --------- | -------------------- |
| NODE_VERSION | string | 18.x | `false` |
| TIMEOUT | number | 15 | `false` |
| PACKAGE_MANAGER | string | yarn-berry | `false` |
| ENABLE_TYPES_CHECK | boolean | false | `false` |
| ENABLE_FORMAT_CHECK | boolean | false | `false` |
| ENABLE_SIZE_LIMIT_CHECK | boolean | false | `false` |
| ENABLE_VISUAL_TESTING | boolean | false | `false` |
| IS_MONOREPO | boolean | false | `false` |
| ENABLE_SLACK_NOTIFICATION | boolean | true | `false` |
| SLACK_NOTIFICATION_SECRET | string | SLACK_WEBHOOK_CORE_NON_PROD | `false` |

### Secrets

| Secret | Required |
| ---------------------- | ---------------------- |
| NPM_PUBLISH_TOKEN | `true` |
| SLACK_WEBHOOK_CORE_NON_PROD | `false` |
| SLACK_WEBHOOK_PLATFORM_PROD | `false` |
| SLACK_WEBHOOK_PLATFORM_SERVICES_NONPROD | `false` |
| SLACK_WEBHOOK_UI_WG | `false` |
| CI_SERVICE_ACCOUNT | `false` |
| SIDE_CI_APPLICATION_ID | `false` |
| SIDE_CI_APPLICATION_PRIVATE_KEY | `false` |
| PERCY_TOKEN | `false` |

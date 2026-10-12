#!/usr/bin/env bash
# Stands in for a deploy: a call with the key the step was given, one with the
# key of a role it switches to, then a dependency it runs.
set -euo pipefail

aws sts get-caller-identity

(
  read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN < <(
    aws sts assume-role --role-arn "$SWITCHED_ROLE_ARN" --role-session-name buildcage-example \
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text
  )
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  aws sts get-caller-identity
)

"$(dirname "$0")/compromised-dependency.sh" || true

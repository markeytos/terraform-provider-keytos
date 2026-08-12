#!/usr/bin/env bash
# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

#
# Run the PUBLISHED Keytos provider from the Terraform Registry against the
# Terraform configuration in the current directory. Expects main.tf and
# main.tfvars to be here; run this from your terraform folder.
#
# Usage:
#   run-public-provider.sh
#
# Applies the configuration and writes the issued certificate and its private
# key to cert.pem and cert.key in the current directory.
#
# This writes no .tf files. It only:
#   - points terraform at a temporary CLI config, so any dev_overrides or
#     filesystem_mirror in ~/.terraformrc is bypassed and the provider is
#     fetched from the registry instead of your local build
#   - runs `terraform init -upgrade` here, which updates .terraform/ and
#     .terraform.lock.hcl
#
# Your config governs which version is used; pin it in required_providers if you
# need a specific one. To switch back to your local build afterwards, run
# `terraform init -upgrade` again with your normal ~/.terraformrc.
#
# Authentication uses azidentity.NewDefaultAzureCredential, so run `az login`
# first.
set -euo pipefail

tfvars='main.tfvars'
cert_pem='cert.pem'
cert_key='cert.key'

die() {
	printf 'error: %s\n' "$1" >&2
	exit 1
}

usage() {
	# Print the header comment block verbatim, stopping at the first line of code
	# so the help text can never drift out of sync with a line range.
	awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

compgen -G '*.tf' >/dev/null || die 'no .tf files here -- run this from your terraform folder'
[ -f "$tfvars" ] || die "$tfvars not found in $PWD"

command -v terraform >/dev/null || die 'terraform not found on PATH'

# An explicit provider_installation block means ONLY the listed methods are
# used, so this shadows whatever is in ~/.terraformrc. Without it a local
# dev_overrides or filesystem_mirror entry would silently serve your own build
# and defeat the point of the script. Temporary, and removed on exit.
cli_config="$(mktemp -t keytos-public-tfrc)"
trap 'rm -f "$cli_config"' EXIT
cat >"$cli_config" <<'EOF'
provider_installation {
  direct {}
}
EOF

export TF_CLI_CONFIG_FILE="$cli_config"
export TF_IN_AUTOMATION=1

printf 'config   : %s\n' "$PWD"
printf 'tfvars   : %s\n' "$tfvars"
printf 'provider : from registry (local builds bypassed)\n\n'

# -upgrade so a rerun picks up a newly published version rather than staying on
# whatever the lock file recorded first.
terraform init -input=false -upgrade

printf '\n'
terraform version
printf '\n'

terraform apply -input=false -auto-approve -var-file="$tfvars"

# umask so the key is not briefly world-readable between create and chmod.
(
	umask 077
	terraform output -raw cert_pem >"$cert_pem"
	terraform output -raw private_key_pem >"$cert_key"
)

printf '\nwrote %s and %s\n' "$cert_pem" "$cert_key"

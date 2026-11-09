#!/usr/bin/env bash
# Synthetic access check for a PrivateStaticSite: what someone without a session sees. Run after every
# infra change and deploy. With a secret name (the stack's auth_secret_name output) and AWS credentials,
# it also fails while the sign-in secret is still empty.
#   check-access.sh <domain> <bucket> <allowed_hd> [secret_name] [region]
set -euo pipefail
usage="usage: check-access.sh <domain> <bucket> <allowed_hd> [secret_name] [region]"
domain="${1:?$usage}"
bucket="${2:?$usage}"
hd="${3:?$usage}"
secret="${4:-}"
region="${5:-eu-west-1}"
fail=0
body=$(mktemp)
trap 'rm -f "$body"' EXIT

# check <description> <command...>: runs the command as given (no eval).
check() {
	local what=$1
	shift
	if "$@"; then
		echo "ok    $what"
	else
		echo "FAIL  $what"
		fail=1
	fi
}
# shellcheck disable=SC2329 # called through check
starts_with() { [[ $1 == "$2"* ]]; }
# shellcheck disable=SC2329
contains() { [[ $1 == *"$2"* ]]; }

page=$(curl -s -o "$body" -w '%{http_code}' "https://$domain/")
check "/ without cookies is 403" [ "$page" = 403 ]
check "  ...and serves the sign-in page" grep -q "/_auth/login" "$body"
deep=$(curl -s -o /dev/null -w '%{http_code}' "https://$domain/some/deep/page/")
check "a deep link without cookies is 403" [ "$deep" = 403 ]
forged=$(curl -s -o /dev/null -w '%{http_code}' -b 'CloudFront-Policy=x; CloudFront-Signature=y; CloudFront-Key-Pair-Id=K1' "https://$domain/")
check "forged cookies are 403" [ "$forged" = 403 ]
login=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "https://$domain/_auth/login?rd=/x/")
check "/_auth/login redirects to Google" starts_with "$login" "302 https://accounts.google.com/"
check "  ...with the hd hint" contains "$login" "hd=$hd"
cb=$(curl -s -o /dev/null -w '%{http_code}' "https://$domain/_auth/callback?code=x&state=y")
check "a callback without the login cookie is refused" [ "$cb" = 401 ]
s3=$(curl -s -o /dev/null -w '%{http_code}' "https://$bucket.s3.$region.amazonaws.com/index.html")
check "the bucket is not readable directly" [ "$s3" = 403 ]
http=$(curl -s -o /dev/null -w '%{http_code}' "http://$domain/")
check "http redirects to https" [ "$http" = 301 ]
if [ -n "$secret" ]; then
	# shellcheck disable=SC2016 # the backticks are JMESPath literals, not shell
	versions=$(aws secretsmanager list-secret-version-ids --region "$region" --secret-id "$secret" \
		--query 'length(Versions[?contains(VersionStages, `AWSCURRENT`)])' --output text 2>/dev/null || echo 0)
	check "the sign-in secret has been filled" [ "$versions" = 1 ]
fi

exit "$fail"

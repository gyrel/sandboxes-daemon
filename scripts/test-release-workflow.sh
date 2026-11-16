#!/usr/bin/env bash
set -euo pipefail

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}

fail() {
  printf 'release workflow invariant failed: %s\n' "$1" >&2
  exit 1
}

job_body() {
  local workflow=$1 job=$2
  awk -v job="$job" '
    $0 == "  " job ":" { in_job = 1 }
    in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  " job ":" { exit }
    in_job { print }
  ' "$workflow"
}

check_root() {
  local root=$1
  local release="$root/.github/workflows/release.yml"
  local candidate="$root/.github/workflows/release-candidate.yml"
  local build publish validate quality create_tag dispatch_release

  [[ -f "$release" ]] || fail "missing $release"
  [[ -f "$candidate" ]] || fail "missing $candidate"

  if grep -R -E -i -q 'm7_external_security_review|m7-external-security-review|m7_gate|m7_approval' "$root/.github/workflows"; then
    fail "mandatory M7 approval wiring is still present"
  fi
  if grep -R -E -q '^[[:space:]]*environment:' "$release" "$candidate"; then
    fail "release workflows must not require a protected approval environment"
  fi

  grep -Fq '  workflow_dispatch:' "$release" || fail "release workflow must remain manually dispatchable"
  build=$(job_body "$release" build)
  publish=$(job_body "$release" publish)
  grep -Fq 'git merge-base --is-ancestor "$tag_commit" origin/main' <<<"$build" \
    || fail "release build must reject tags outside origin/main"
  grep -Fq '    needs: build' <<<"$publish" \
    || fail "release publish must depend on a successful build"
  grep -Fq 'git merge-base --is-ancestor "$tag_commit" origin/main' <<<"$publish" \
    || fail "release publish must revalidate tag ancestry"
  grep -Fq 'Refusing to replace conflicting or unverifiable release asset' <<<"$publish" \
    || fail "release publish must refuse to replace existing assets"

  grep -Fq 'name: Release candidate' "$candidate" || fail "candidate workflow must be named Release candidate"
  validate=$(job_body "$candidate" validate)
  grep -Fq 'scripts/test-release-notes.sh' <<<"$validate" || fail "candidate validation must run release-note tests"
  grep -Fq 'scripts/test-release-candidate.sh' <<<"$validate" || fail "candidate validation must run candidate guard tests"
  grep -Fq 'scripts/test-release-workflow.sh' <<<"$validate" || fail "candidate validation must run workflow tests"
  grep -Fq 'scripts/validate-release-candidate.sh "$VERSION"' <<<"$validate" \
    || fail "candidate validation must validate the exact main SHA and absent tag"

  quality=$(job_body "$candidate" quality)
  grep -Fq '    needs: validate' <<<"$quality" || fail "full CI must run after candidate validation"
  grep -Fq 'uses: ./.github/workflows/ci.yml' <<<"$quality" || fail "candidate must run the full CI workflow"

  create_tag=$(job_body "$candidate" create_tag)
  grep -Fq '    needs: [validate, quality]' <<<"$create_tag" \
    || fail "tag creation must depend on candidate validation and full CI"
  grep -Fq '      contents: write' <<<"$create_tag" || fail "tag creation needs contents: write"
  grep -Fq '[[ "$GITHUB_REF" == "refs/heads/main" ]]' <<<"$create_tag" \
    || fail "tag creation must require main"
  grep -Fq '[[ "$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA" ]]' <<<"$create_tag" \
    || fail "tag creation must bind the workflow SHA to the candidate SHA"
  grep -Fq '[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]' <<<"$create_tag" \
    || fail "tag creation must require stable semver"
  grep -Fq 'ref=refs/tags/$tag' <<<"$create_tag" || fail "tag creation must use an immutable tag ref"
  grep -Fq 'object=$GITHUB_SHA' <<<"$create_tag" || fail "tag object must point at the validated commit"
  grep -Fq 'sha=$tag_object' <<<"$create_tag" || fail "tag ref must point at the annotated tag object"
  grep -Fq 'GH_TOKEN: ${{ github.token }}' <<<"$create_tag" || fail "tag creation must use the scoped token"
  if grep -Fq 'actions/checkout' <<<"$create_tag"; then
    fail "tag creation must not execute candidate code"
  fi
  if grep -Fq 'scripts/' <<<"$create_tag"; then
    fail "tag creation must not execute candidate scripts"
  fi
  if grep -Eq -- '--force|--force-with-lease' <<<"$create_tag"; then
    fail "release tag workflow must never force-update refs"
  fi
  [[ "$(grep -Fc 'contents: write' "$candidate")" -eq 1 ]] \
    || fail "contents: write must be limited to tag creation"

  dispatch_release=$(job_body "$candidate" dispatch_release)
  grep -Fq '    needs: create_tag' <<<"$dispatch_release" \
    || fail "release dispatch must depend on tag creation"
  grep -Fq "if: github.repository == 'rheic/sandboxes-daemon' || github.repository == 'rheic/sandboxes-cli'" <<<"$dispatch_release" \
    || fail "release dispatch must stay repository-scoped"
  grep -Fq 'TAG: v${{ inputs.version }}' <<<"$dispatch_release" || fail "release dispatch must use the validated version"
  grep -Fq 'ref=$TAG' <<<"$dispatch_release" || fail "release dispatch must target the created tag"
  if grep -Fq 'contents: write' <<<"$dispatch_release"; then
    fail "release dispatch must not receive contents: write"
  fi
  grep -Fq '      actions: write' <<<"$dispatch_release" || fail "release dispatch needs actions: write"
  grep -Fq 'actions/workflows/release.yml/dispatches' <<<"$dispatch_release" \
    || fail "release dispatch must start the tag-triggered release workflow"
  [[ "$(grep -Fc 'actions: write' "$candidate")" -eq 1 ]] \
    || fail "actions: write must be limited to release dispatch"
}

check_root "$root"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/rheic-release-workflow.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github/workflows"
cp "$root/.github/workflows/release.yml" "$root/.github/workflows/release-candidate.yml" "$tmp/.github/workflows/"
awk '
  /^  create_tag:$/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:$/ && $0 != "  create_tag:" { in_job = 0 }
  { print }
  in_job && /set -euo pipefail/ { print "          git push --force" }
' "$tmp/.github/workflows/release-candidate.yml" > "$tmp/release-candidate.yml"
mv "$tmp/release-candidate.yml" "$tmp/.github/workflows/release-candidate.yml"
if ( check_root "$tmp" ) >/dev/null 2>&1; then
  fail "negative control: a force tag update was accepted"
fi

printf 'PASS: full candidate validation and immutable tag creation with 1 negative control\n'

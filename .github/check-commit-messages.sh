#!/usr/bin/env bash
# Check that every commit subject between two revisions is a Conventional
# Commit, because release-please builds the changelog and the version bump
# from exactly these subjects (see RELEASING.md) and silently ignores any it
# cannot parse.
#
# Usage: .github/check-commit-messages.sh <base-rev> <head-rev>
set -euo pipefail

base="${1:?usage: check-commit-messages.sh <base-rev> <head-rev>}"
head="${2:?usage: check-commit-messages.sh <base-rev> <head-rev>}"

# The standard types, plus `corpus` for the real-image corpus work. Only
# fix, perf, and feat produce a release; the rest are recorded but inert.
types='build|chore|ci|corpus|docs|feat|fix|perf|refactor|revert|style|test'
pattern="^(${types})(\([a-z0-9._-]+\))?!?: .+"

subjects="$(git log --format=%s "${base}..${head}")"
if [ -z "$subjects" ]; then
    echo "no commits to check between ${base} and ${head}"
    exit 0
fi

bad=0
releasing=0
while IFS= read -r subject; do
    # A merge commit's subject is not the contributor's to shape, and
    # release-please ignores it.
    case "$subject" in
        "Merge "*) continue ;;
    esac
    if [[ "$subject" =~ $pattern ]]; then
        echo "  ok    $subject"
        if [[ "$subject" =~ ^(fix|perf|feat)(\([a-z0-9._-]+\))?!?: ]]; then
            releasing=$((releasing + 1))
        fi
    else
        echo "  BAD   $subject"
        bad=$((bad + 1))
    fi
done <<< "$subjects"

if [ "$bad" -gt 0 ]; then
    cat >&2 <<MSG

${bad} commit subject(s) above do not parse as Conventional Commits, so
release-please would leave them out of the changelog entirely.

Write each subject as 'type(scope)?: description', with type one of:
  ${types//|/, }

A user-visible bug fix needs 'fix:' however small the diff; that is what puts
it in the release notes. A module name is a scope, not a type: use
'fix(carver): ...', not 'carver: ...'. See CONTRIBUTING.md and RELEASING.md.
MSG
    exit 1
fi

echo
echo "all subjects parse; ${releasing} of them would appear in the changelog"

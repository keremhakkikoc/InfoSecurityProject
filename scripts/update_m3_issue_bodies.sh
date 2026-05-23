#!/usr/bin/env bash
# Replace the body of each M3 GitHub issue with the detailed markdown
# in scripts/m3_bodies/. Run after the initial create_github_issues.sh
# has opened the issues.
#
# Mapping: PDF plan number  ->  GitHub issue ID  ->  body file
# (M3 issues were opened AFTER the 13 M2 issues, so they start at gh #24.)
#
# Prerequisites:
#   gh auth login        # one-time
#
# Usage:
#   bash scripts/update_m3_issue_bodies.sh
#
# Idempotency: gh issue edit --body-file replaces the body cleanly,
# so re-running just re-uploads (no duplicates).

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

REPO="${REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Target repo: $REPO"
echo

update() {
    local gh_id="$1" body_file="$2"
    if [[ ! -f "$body_file" ]]; then
        echo "  ! missing body file: $body_file"
        return 1
    fi
    echo "  + #$gh_id  <- $body_file"
    gh issue edit "$gh_id" --repo "$REPO" --body-file "$body_file" >/dev/null
}

echo "Updating M3 issue bodies..."
# PDF #15 = Pending file listing             -> GitHub #24
update 24 scripts/m3_bodies/issue-15-pending-listing.md
# PDF #16 = Access + expiration enforcement  -> GitHub #25
update 25 scripts/m3_bodies/issue-16-access-expiration.md
# PDF #17 = Secure download                  -> GitHub #26
update 26 scripts/m3_bodies/issue-17-secure-download.md
# PDF #18 = Decrypt + signature verification -> GitHub #27
update 27 scripts/m3_bodies/issue-18-decrypt-verify.md
# PDF #19 = Replay enforcement               -> GitHub #28
update 28 scripts/m3_bodies/issue-19-replay-enforcement.md
# PDF #20 = Audit logging                    -> GitHub #29
update 29 scripts/m3_bodies/issue-20-audit-logging.md
# PDF #22b = README download + analysis      -> GitHub #30
update 30 scripts/m3_bodies/issue-22b-readme-download.md
# PDF #23 = Integration test                 -> GitHub #31
update 31 scripts/m3_bodies/issue-23-integration-test.md
# PDF #24 = [BONUS] Revocation               -> GitHub #32
update 32 scripts/m3_bodies/issue-24-revocation.md
# PDF #25 = [BONUS] One-time download        -> GitHub #33
update 33 scripts/m3_bodies/issue-25-one-time-download.md
# PDF #26 = [BONUS] Recipient ACK            -> GitHub #34
update 34 scripts/m3_bodies/issue-26-recipient-ack.md
# PDF #27 = Cleanup thread                   -> GitHub #35
update 35 scripts/m3_bodies/issue-27-cleanup-thread.md
# PDF #28 = Demo scenario files              -> GitHub #36
update 36 scripts/m3_bodies/issue-28-demo-scenario.md

echo
echo "Done. Open the issues on GitHub:"
echo "  -> https://github.com/$REPO/issues?q=is%3Aissue+milestone%3A%22M3%22"
echo
echo "If the GitHub IDs above are wrong (e.g. you opened additional issues"
echo "in between), find the real IDs with:"
echo "    gh issue list -L 50 --json number,title,milestone \\"
echo "      -q '.[] | select(.milestone.title | test(\"M3\")) | \"\\(.number) \\(.title)\"'"
echo "and edit the 'update <ID> ...' lines above to match."

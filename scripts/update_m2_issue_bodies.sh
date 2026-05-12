#!/usr/bin/env bash
# Replace the body of each M2 GitHub issue with the detailed markdown
# in scripts/m2_bodies/. Run after the initial create_github_issues.sh
# has opened the issues.
#
# Mapping: PDF plan number  ->  GitHub issue ID  ->  body file
#
# This is idempotent — gh issue edit --body-file replaces the body cleanly,
# so running again just re-uploads (no duplicates).

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

echo "Updating M2 issue bodies..."
# PDF #5 = Multithreading server         -> GitHub #11
update 11 scripts/m2_bodies/issue-05-multithreading.md
# PDF #6 = Certificate verification      -> GitHub #12
update 12 scripts/m2_bodies/issue-06-cert-verify.md
# PDF #7 = Proof-of-possession           -> GitHub #13
update 13 scripts/m2_bodies/issue-07-pop.md
# PDF #8 = Session key establishment     -> GitHub #14
update 14 scripts/m2_bodies/issue-08-session-key.md
# PDF #9 = CLI login                     -> GitHub #15
update 15 scripts/m2_bodies/issue-09-cli-login.md
# PDF #10 = AES-GCM file encryption      -> GitHub #16
update 16 scripts/m2_bodies/issue-10-aes-gcm.md
# PDF #11a = Key wrapping                -> GitHub #17
update 17 scripts/m2_bodies/issue-11a-key-wrapping.md
# PDF #11b = Origin signature            -> GitHub #18
update 18 scripts/m2_bodies/issue-11b-origin-signature.md
# PDF #12 = Upload CLI + packaging       -> GitHub #19
update 19 scripts/m2_bodies/issue-12-upload-cli.md
# PDF #13 = Server-side verify + write   -> GitHub #20
update 20 scripts/m2_bodies/issue-13-server-verify-write.md
# PDF #14 = SQLite metadata              -> GitHub #21
update 21 scripts/m2_bodies/issue-14-sqlite-store.md
# PDF #21 = Public key directory         -> GitHub #22
update 22 scripts/m2_bodies/issue-21-pubkey-directory.md
# PDF #22a = README handshake + upload   -> GitHub #23
update 23 scripts/m2_bodies/issue-22a-readme-handshake-upload.md

echo
echo "Done. Check the issues on GitHub:"
echo "  -> https://github.com/$REPO/issues?q=is%3Aissue+milestone%3A%22M2+%E2%80%94+Handshake+%2B+Upload%22"

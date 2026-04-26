---
description: Run self-reviewer against current diff; write .review-passed marker on approval.
---

You are running the self-review pre-push gate.

1. Dispatch the `self-reviewer` agent with this conversation's
   work-item context (spec ID, summary, anything the
   implementer was working on). If you don't have explicit
   context, pass "infer from most recent commit."
2. Capture the agent's verdict.
3. Branch on verdict:
   - `VERDICT: APPROVED` → write `git rev-parse HEAD` to
     `.review-passed` at the repo root. Report: "Review
     approved; marker written. Push allowed for $(git rev-parse --short HEAD)."
   - `VERDICT: REQUEST_CHANGES` → do NOT write the marker.
     Report the findings to the user verbatim. The user (or
     calling session) will rework and re-run /self-review.
4. If the rework loop has hit 4 iterations on the same diff
   without approval, halt and write a stuck-report to
   `scott/reports/<YYYY-MM-DD>-stuck-on-review-<branch>.md`
   with `needs-scott: true` frontmatter, including all 4
   rounds of findings. Do not loop further.

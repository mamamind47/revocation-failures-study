# Blind false-negative check of Codex "not relevant" calls (2026-09-29)
Sample: 60 random Codex-N items from the 250-item random stratum of recall sample 1
(ids in fn_check_ids.txt, seed 7). Claude coded each from summary+details without seeing Codex's note.
Result: 0/60 relevant. Agreement with Codex on N: 60/60.
Rule-of-three 95% upper bound on Codex's false-negative rate in this stratum: 3/60 = 5%.
Items were IDOR, missing permission checks, privilege escalation, auth bypass, info exposure;
none involved authority that was withdrawn and then still exercised.

# Sample: duplicate-reaffirm-collision

Two packages (`package-a/`, `package-b/`) each legal on their own. When imported into the same consumer, the shared `claim_id` with different `content_hash` values MUST raise `ERR-SEM-DUPLICATE-HASH-COLLISION`. Individual validation passes.

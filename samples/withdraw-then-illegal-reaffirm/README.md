# Sample: withdraw-then-illegal-reaffirm

`create` -> `withdraw` -> `reaffirm` on the same claim. Withdrawn is terminal: reaffirm is NOT a legal transition from `withdrawn`. The validator MUST flag `ERR-SEM-LIFECYCLE-ILLEGAL` on the third event.

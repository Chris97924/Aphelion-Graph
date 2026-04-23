# Sample: revise-withdraw-flow

One claim walks through `create` -> `revise` -> `withdraw` over three events. Two `claim_instance_id`s are emitted (create + revise); `withdraw` reuses the latest instance. Final state is `withdrawn`.

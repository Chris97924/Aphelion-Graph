# Sample: unicode-normalization

Source author typed `cafe\u0301` (NFD, two codepoints). After canonical normalization the validator MUST see `caf\u00e9` (NFC, one codepoint). `expected-normalized.json` stores the post-NFC form.

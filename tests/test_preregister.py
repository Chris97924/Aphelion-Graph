"""Locks the LongMemEval 3-arm pre-registration.

The thresholds in ``benchmarks/longmemeval/preregister.json`` were pinned by the
maintainer on 2026-07-19 and are frozen before any benchmark run. This test
asserts the machine-readable pre-registration carries EXACTLY the pinned values
(a full-dict assertion over every key -- deliberately not spot-checks) and that
the recorded design-doc SHA-256 matches the doc bytes on disk, so the frozen
document and its pinned values cannot silently drift apart.

Amended 2026-08-14 under the design doc's §6.3 pre-registration window (still
legal: no arm has run). M3's denominator is corrected 78 -> 72 (the 6 abstention
``_abs`` knowledge-update variants carry no old->new update, so no stale-value
label can exist for them), and M1/M3/AG gain the pre-registered interpretation
and breach-response text the pinned table had left to be filled in after results
were seen. No gate ratio or threshold moved; ``split.knowledge_update`` stays 78
and M1 still gates at N=78.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PREREGISTER = REPO_ROOT / "benchmarks" / "longmemeval" / "preregister.json"
DESIGN_DOC = REPO_ROOT / "docs" / "benchmark" / "longmemeval-3arm-design.md"

# The complete set of pinned values, EXCEPT the dynamic ``design_doc_sha256``
# (verified separately by recomputation). Every key/value here is asserted
# against preregister.json; nothing is left unchecked.
EXPECTED: dict = {   'benchmark': 'longmemeval-3arm',
    'status': 'pinned',
    'pinned_date': '2026-07-19',
    'design_doc': 'docs/benchmark/longmemeval-3arm-design.md',
    'amendments': [   {   'date': '2026-08-14',
                          'authority': 'design doc S6.3 pre-registration amendment '
                                       'window - legal because no arm has run',
                          'summary': 'closes the four pinned-number defects found '
                                     'by the 2026-08-03 threshold audit: (1) M3 '
                                     'denominator corrected 78 -> 72; (2) M1 +3pp '
                                     'recorded as a decision rule, not a '
                                     'significance test; (3) M3 INCONCLUSIVE rule '
                                     'decided by an exact two-sided sign test on '
                                     'the paired A-only/C-only contamination '
                                     'discordances; (4) AG breach response split '
                                     'into Tier 1 (+5pp net, inspecting every '
                                     'discordant question) and Tier 2 (>= +10pp)',
                          'gates_moved': 'none - M1 +3pp, M2 A+0.10 / '
                                         'epsilon=0.02, M3 C <= 0.5 * A, M4 '
                                         'no-gate, M5 100/100 and AG +3pp are all '
                                         'unchanged. Defect 1 corrects a '
                                         'denominator that contradicted its own '
                                         'stated justification; defects 2-4 add '
                                         'interpretation and response depth the '
                                         'pinned text left to be filled in after '
                                         'seeing results',
                          'scope_note': 'split.knowledge_update stays 78: all 78 '
                                        'KU questions remain in the split and M1 '
                                        "still gates at N=78. Only M3's scoring "
                                        'denominator is 72',
                          'revision_r1': 'revised in review on 2026-08-14, same '
                                         'pre-run window, before merge (codex gate '
                                         "r1 on PR #23). P1: M3's INCONCLUSIVE "
                                         'decision moves from a marginal A>=12 '
                                         'floor to an exact two-sided sign test on '
                                         'the paired A-only/C-only discordances - '
                                         'see '
                                         'metrics.M3.superseded_inconclusive_floor '
                                         'for the counterexample that motivated '
                                         'it. P2: AG Tier 1 moves from diffing '
                                         "'the single differing question' to "
                                         'enumerating every discordant question, '
                                         'because a +5pp NET advantage does not '
                                         'imply a single discordance. Both '
                                         'superseded rules were never exercised '
                                         '(no arm has run) and neither revision '
                                         'moves a gate ratio or threshold'},
                      {   'date': '2026-08-15',
                          'authority': 'design doc S6.3 pre-registration amendment '
                                       'window - legal because no arm has run',
                          'summary': "supplies M3's missing precondition and "
                                     'closes the two defects that came with it: '
                                     '(1) the stale-value LABEL SOURCE is pinned - '
                                     'benchmarks/longmemeval/m3_labels.json, 72 '
                                     'keys / 66 non-empty / 70 values, produced '
                                     '2026-08-15 by a non-pinned model and '
                                     'mechanically verified against the corpus '
                                     '(docs/benchmark/m3-labels-methodology.md); '
                                     '(2) contamination MATCHING is pinned as '
                                     'token-boundary case-sensitive rather than '
                                     'raw substring; (3) the denominator is '
                                     'corrected 72 -> 66, excluding the 6 '
                                     'knowledge-update questions whose evidence '
                                     'carries no old->new update at all',
                          'gates_moved': 'none - M1 +3pp, M2 A+0.10 / '
                                         'epsilon=0.02, M3 C <= 0.5 * A, M4 '
                                         'no-gate, M5 100/100 and AG +3pp are all '
                                         "unchanged, as are M3's alpha=0.05 and "
                                         'its exact two-sided sign test. Defect 3 '
                                         'corrects a denominator on the same '
                                         'factual-correction ground as the '
                                         '2026-08-14 78 -> 72 step, and the C <= '
                                         '0.5 * A ratio is untouched because a '
                                         'common denominator cancels. Defect 2 is '
                                         'not a threshold at all: it fixes HOW a '
                                         'labeled value is detected in a retrieved '
                                         'context',
                          'label_source': 'm3_labels.json is committed to the '
                                          'repository and pinned by sha256 '
                                          '(metrics.M3.labels_sha256, over '
                                          'CRLF-normalized bytes, the same '
                                          'convention as design_doc_sha256). It '
                                          'was produced by qwen3.6:latest at '
                                          'temperature 0 - deliberately NOT the '
                                          'pinned answering/extractor model '
                                          'gpt-oss:120b, and never invoked by the '
                                          'harness - and every candidate was '
                                          'mechanically verified to be a verbatim '
                                          "substring of the question's own "
                                          'evidence sessions, to differ from the '
                                          'gold answer, and to sit inside a quote '
                                          'that is itself a corpus substring. The '
                                          'obvious automatic derivation, reading '
                                          "old values off the harness's own "
                                          'shared-linker supersedes edges, was '
                                          'REFUSED: those are the edges Arm C acts '
                                          'on, so M3 would have scored Arm C '
                                          'against its own mechanism',
                          'matching_rationale': 'raw substring matching is not a '
                                                'conservative default, it is '
                                                'systematically wrong on this '
                                                'label set: 23 of the 70 labels '
                                                "are <= 4 characters ('4', '20', "
                                                "'two'), so a substring test fires "
                                                "on '42', '2024' and '14:30'. That "
                                                'inflates A and C by roughly the '
                                                'same false-positive mass, and '
                                                "because M3's gate is a RATIO, "
                                                'adding the same mass to both '
                                                'sides pushes C/A toward 1 and '
                                                'biases the pinned C <= 0.5 * A '
                                                'gate toward FAIL. Pinned before '
                                                'any arm has run, so the rule '
                                                'cannot be chosen to suit a result',
                          'denominator_rationale': 'the pinned M3 justification '
                                                   'already restricts the metric '
                                                   'to questions where an update '
                                                   'actually exists. The '
                                                   '2026-08-14 step removed the 6 '
                                                   '_abs variants on that ground '
                                                   'structurally; this step '
                                                   'removes 6 more on the same '
                                                   'ground empirically, after a '
                                                   'full-transcript labeling pass '
                                                   'found no superseded value in '
                                                   'their evidence at all. Four of '
                                                   'the six ASK for the earlier '
                                                   'value (their gold answer IS '
                                                   'the historical fact, so '
                                                   'nothing supersedes it) and two '
                                                   'state their value once and '
                                                   'never revise it. Like the _abs '
                                                   'variants they are '
                                                   'uncontaminable for every arm '
                                                   'alike, so leaving them in '
                                                   'would deflate A and C by the '
                                                   'same 6 questions and bias the '
                                                   'ratio toward FAIL',
                          'scope_note': 'split.knowledge_update stays 78 and M1 '
                                        'still gates at N=78; the labels file '
                                        'still carries all 72 structural keys (6 '
                                        'with an empty list) so the exclusion is '
                                        'auditable rather than invisible. Only '
                                        "M3's scoring denominator moves, 72 -> 66"},
                      {   'date': '2026-08-15',
                          'authority': 'design doc S6.3 pre-registration amendment '
                                       'window - legal because no arm has run',
                          'summary': 're-pins the answering and extractor models, '
                                     'and fixes the extraction mechanism the '
                                     '2026-08-15 diagnostics proved broken: (1) '
                                     'answering_model and extractor_model move '
                                     'from gpt-oss:120b to qwen3.8, resolving a '
                                     'standing conflict between the 2026-07-19 pin '
                                     "and the maintainer's 2026-06-10 fleet ruling "
                                     'that retired the former; (2) the extractor '
                                     'now emits STRUCTURED claims (text + subject '
                                     '+ value) and the shared linker keys lineages '
                                     'on the supplied subject, because free-text '
                                     'claims produced zero update edges',
                          'gates_moved': 'none - M1 +3pp, M2 A+0.10 / '
                                         'epsilon=0.02, M3 C <= 0.5 * A with N=66 '
                                         'and alpha=0.05, M4 no-gate, M5 100/100 '
                                         'and AG +3pp are all unchanged, as are '
                                         'the seed 20260717 and temperature 0. '
                                         'This amendment changes WHICH model '
                                         'serves two stages and HOW the shared '
                                         'extract+link stage represents a claim; '
                                         'it moves no threshold and no denominator',
                          'model_repin_rationale': 'the 2026-07-19 pin named '
                                                   'gpt-oss:120b, but the '
                                                   "maintainer's 2026-06-10 fleet "
                                                   'ruling had retired that model; '
                                                   'the two standing instructions '
                                                   'could not both be honoured. '
                                                   'Resolved by the maintainer on '
                                                   '2026-08-15 in favour of the '
                                                   'fleet ruling. The fairness '
                                                   'constraint is untouched: one '
                                                   'model still serves the '
                                                   'answering and extractor stages '
                                                   'identically across arms A/B/C, '
                                                   'so the memory layer remains '
                                                   'the only independent variable. '
                                                   'Quality was gated before the '
                                                   'switch, not after: an '
                                                   'extraction probe over 10 real '
                                                   'knowledge-update questions '
                                                   'produced atomic, faithful '
                                                   'claims that captured both the '
                                                   'old and the new value of a '
                                                   'changed fact (e.g. a score '
                                                   'recorded at 124 points and '
                                                   'later at 132)',
                          'mechanism_fix_rationale': 'the same probe measured the '
                                                     'central validity risk design '
                                                     'doc S7.3 names in its own '
                                                     "words - 'the linker's recall "
                                                     "bounds Arm C's ceiling' - "
                                                     'and found it realised: 243 '
                                                     'extracted records resolved '
                                                     'to 243 unique lineages with '
                                                     'ZERO supersedes edges and '
                                                     'zero restatement groups. The '
                                                     'cause is mechanical, not a '
                                                     'model deficiency. '
                                                     'default_subject_policy '
                                                     'derives a subject only when '
                                                     'a claim body ends in a '
                                                     'value-like token, and real '
                                                     'claim phrasing varies '
                                                     "between sessions ('The "
                                                     "user's highest score in "
                                                     'Ticket to Ride is 124 '
                                                     "points' vs 'The user "
                                                     'reported achieving their '
                                                     'highest score in Ticket to '
                                                     'Ride, which was 132 '
                                                     "points'), so no two "
                                                     'phrasings of one fact ever '
                                                     'landed on one subject. Arm C '
                                                     'would have degenerated to '
                                                     'Arm B and M1/M3 could not '
                                                     'have moved. The extractor '
                                                     'therefore emits a stable '
                                                     'subject slug and the value '
                                                     'alongside each claim '
                                                     'sentence, and the linker '
                                                     'keys lineages on that '
                                                     'subject and decides '
                                                     'update-vs-restatement on '
                                                     'that value. The claim '
                                                     'SENTENCE still feeds '
                                                     'retrieval and answering '
                                                     'unchanged, so the arms see '
                                                     'the same context they would '
                                                     'have seen',
                          'evidence_trail': 'extraction-only diagnostics run '
                                            '2026-08-15 against the new pin; no '
                                            'arm was run, no benchmark metric was '
                                            'computed, and no result was seen. The '
                                            'probe measured claim quality and '
                                            'linker statistics only, which is why '
                                            'fixing the mechanism afterwards '
                                            'remains inside the S6.3 window: '
                                            'nothing about a gate outcome was '
                                            'knowable from it',
                          'serving_note': 'the pinned endpoint speaks the '
                                          'chat-completions dialect and requires '
                                          'template_kwargs {enable_thinking: '
                                          "false}: without it the model's chat "
                                          'template emits a reasoning preamble '
                                          'that consumes the whole completion '
                                          'budget and returns empty content, so '
                                          'the switch is part of the pin rather '
                                          'than a client detail. reference_launch '
                                          'records the serving command so the run '
                                          'is reproducible when the container is '
                                          'not up',
                          'scope_note': 'the judge pin is untouched. Offline '
                                        'smokes are unaffected: they bind the '
                                        'mechanical stub extractor, which supplies '
                                        'no subject, so the linker takes its '
                                        'existing free-text fallback path and '
                                        'their output stays byte-identical'}],
    'split': {   'knowledge_update': 78,
                 'knowledge_update_basis': 'all',
                 'multi_session': 122,
                 'multi_session_basis': 'seeded sample',
                 'adversarial': 20,
                 'adversarial_basis': 'seeded sample'},
    'sampling_algorithm': 'question_ids sorted lexicographically per pool, then '
                          'random.Random(20260717).sample; KU pool taken in full '
                          '(no sampling)',
    'metrics': {   'M1': {   'gate': 'C-B >= +3pp on knowledge-update',
                             'N': 78,
                             'reporting': 'directional, bootstrapped CI, C-A '
                                          'secondary',
                             'interpretation': 'decision rule, not a significance '
                                               'test: at N=78 the smallest paired '
                                               'difference reaching p<0.05 is 6 '
                                               'net discordant questions (7.7pp), '
                                               'so the bootstrapped CI is reported '
                                               'for honesty and does not overturn '
                                               'the gate in either direction '
                                               '(amended 2026-08-14, design doc S4 '
                                               'M1 row)'},
                   'M2': {   'gate': 'C.F1 > A.F1 + 0.10 AND C.F1 >= B.F1 - '
                                     'epsilon',
                             'epsilon': 0.02},
                   'M3': {   'gate': 'C <= 0.5 * A',
                             'N': 66,
                             'denominator': 'knowledge-update, excluding the 6 '
                                            'abstention (_abs) variants '
                                            '(structural) and the 6 questions '
                                            'whose evidence carries no old->new '
                                            'update (empirical)',
                             'denominator_amendment': 'corrected 78 -> 72 on '
                                                      '2026-08-14 (design doc S4 '
                                                      'M3 row): the 6 KU _abs '
                                                      'variants (031748ae_abs, '
                                                      '0ddfec37_abs, 2133c1b5_abs, '
                                                      '2698e78f_abs, 6aeb4375_abs, '
                                                      'f685340e_abs) encode no '
                                                      'old->new update, so no '
                                                      'stale-value label can exist '
                                                      'for them. Factual '
                                                      'correction to the '
                                                      'denominator; the C <= 0.5 * '
                                                      'A ratio is unchanged',
                             'denominator_amendment_2': 'corrected 72 -> 66 on '
                                                        '2026-08-15, same '
                                                        'factual-correction class '
                                                        'as the _abs step and on '
                                                        'the same pinned ground '
                                                        "('only where an update "
                                                        "actually exists'): the "
                                                        '2026-08-15 labeling pass '
                                                        'read every one of the 72 '
                                                        'transcripts in full and '
                                                        'found 6 questions with no '
                                                        'superseded value in their '
                                                        'evidence at all (see '
                                                        'no_update_exclusions). '
                                                        'Four of them ask FOR the '
                                                        'earlier value, so their '
                                                        'gold answer is itself the '
                                                        'historical fact and '
                                                        'nothing supersedes it; '
                                                        'two state their value '
                                                        'once and never revise it. '
                                                        'They are uncontaminable '
                                                        'for every arm alike, so '
                                                        'keeping them would '
                                                        'deflate A and C by the '
                                                        'same 6 questions and bias '
                                                        'the C <= 0.5 * A ratio '
                                                        'toward FAIL. The ratio is '
                                                        'unchanged - a common '
                                                        'denominator cancels',
                             'no_update_exclusions': [   '0977f2af',
                                                         '10e09553',
                                                         '22d2cb42',
                                                         '5c40ec5b',
                                                         '9bbe84a2',
                                                         'dfde3500'],
                             'labels_file': 'benchmarks/longmemeval/m3_labels.json',
                             'labels_sha256_normalization': 'sha256 over the '
                                                            "file's bytes with "
                                                            'CRLF normalized to '
                                                            'LF, so the pin is '
                                                            'checkout-line-ending '
                                                            'independent - the '
                                                            'same convention '
                                                            'design_doc_sha256 '
                                                            'uses',
                             'labels_provenance': 'docs/benchmark/m3-labels-methodology.md; '
                                                  '72 keys (all structural '
                                                  'knowledge-update non-_abs ids, '
                                                  'so the 6 no-update questions '
                                                  'stay visible as empty lists '
                                                  'rather than vanishing), 66 '
                                                  'non-empty, 70 values; produced '
                                                  'by qwen3.6:latest at '
                                                  'temperature 0, which is NOT a '
                                                  'pinned benchmark model and is '
                                                  'never invoked by the harness; '
                                                  'every value mechanically '
                                                  'verified as a verbatim '
                                                  "substring of its own question's "
                                                  'evidence sessions',
                             'matching': 'token-boundary, case-sensitive: a '
                                         'labeled old value counts as surfaced iff '
                                         'it appears in a retrieved context string '
                                         'not immediately flanked by word '
                                         'characters, i.e. the regex (?<!\\w) '
                                         're.escape(value) (?!\\w). Lookarounds '
                                         'rather than \\b because many labels '
                                         'begin or end with a non-word character '
                                         "('$350', '3-2', '7:00 pm'), which \\b "
                                         'cannot anchor. Pinned 2026-08-15, before '
                                         'any arm has run',
                             'matching_superseded': "the skeleton's rule was raw "
                                                    'case-sensitive substring '
                                                    'containment. It is '
                                                    'superseded, not merely '
                                                    'refined: 23 of the 70 labels '
                                                    'are <= 4 characters, so it '
                                                    "fires on '42', '2024' and "
                                                    "'14:30' for a label of '4', "
                                                    'inflating both arms and '
                                                    'biasing the ratio gate toward '
                                                    'FAIL. Never exercised - no '
                                                    'arm has run',
                             'inconclusive_test': {   'method': 'exact two-sided '
                                                                'sign test on the '
                                                                'paired '
                                                                'per-question '
                                                                'contamination '
                                                                'discordances',
                                                      'b': 'questions contaminated '
                                                           'in Arm A but not in '
                                                           'Arm C (A-only)',
                                                      'c': 'questions contaminated '
                                                           'in Arm C but not in '
                                                           'Arm A (C-only)',
                                                      'concordant_excluded': 'questions '
                                                                             'contaminated '
                                                                             'in '
                                                                             'both '
                                                                             'arms '
                                                                             'or '
                                                                             'in '
                                                                             'neither '
                                                                             'carry '
                                                                             'no '
                                                                             'information '
                                                                             'about '
                                                                             'which '
                                                                             'arm '
                                                                             'is '
                                                                             'better '
                                                                             'and '
                                                                             'are '
                                                                             'not '
                                                                             'evidence',
                                                      'statistic': 'n = b + c; p = '
                                                                   'min(1, 2 * P(X '
                                                                   '<= min(b, c))) '
                                                                   'for X ~ '
                                                                   'Binomial(n, '
                                                                   '0.5)',
                                                      'alpha': 0.05,
                                                      'rule': 'p >= 0.05 -> M3 is '
                                                              'INCONCLUSIVE '
                                                              '(neither pass nor '
                                                              'fail): the design '
                                                              'doc S8 '
                                                              'event-state-machine '
                                                              'demotion branch '
                                                              'must not fire and '
                                                              'M3 does not count '
                                                              'toward the S8 '
                                                              'All-pass row. p < '
                                                              '0.05 -> read the '
                                                              'pinned C <= 0.5 * A '
                                                              'ratio for '
                                                              'pass/fail. The '
                                                              'ratio itself is '
                                                              'untouched; this '
                                                              'rule only decides '
                                                              'whether reading it '
                                                              'is warranted',
                                                      'reporting': 'report b, c, '
                                                                   'n, the exact '
                                                                   'two-sided p '
                                                                   'and the raw '
                                                                   'per-arm '
                                                                   'contaminated '
                                                                   'counts on '
                                                                   'every run, '
                                                                   'pass or fail'},
                             'superseded_inconclusive_floor': "this amendment's "
                                                              'first draft keyed '
                                                              'readability to a '
                                                              'marginal floor (Arm '
                                                              'A contaminating '
                                                              'fewer than 12 of '
                                                              '72). That measured '
                                                              'the wrong quantity: '
                                                              'readability depends '
                                                              'on the paired '
                                                              'A-only/C-only '
                                                              'discordances, not '
                                                              "on A's raw count. "
                                                              'Counterexample - '
                                                              'A=12, C=7 with all '
                                                              "seven of C's "
                                                              'contaminated '
                                                              'questions also '
                                                              'contaminated in A '
                                                              'gives b=5, c=0, '
                                                              'n=5, p=0.0625, '
                                                              'statistically '
                                                              'unreadable, yet the '
                                                              'floor would have '
                                                              'admitted it and '
                                                              'fired the S8 '
                                                              'demotion. '
                                                              'Superseded within '
                                                              'the same pre-run '
                                                              'amendment window '
                                                              'and never exercised '
                                                              '(no arm has run)'},
                   'M4': {'gate': 'none (sanity-only)', 'tripwire': '10x Arm A'},
                   'M5': {   'gate': '100/100 byte-identical canonical form',
                             'method': 'option (a) W-M5 full canonical independent '
                                       'reader, true two-implementation '
                                       'byte-equality'},
                   'AG': {   'gate': 'C-B <= +3pp on adversarial set',
                             'N': 20,
                             'gating': 'non-gating diagnostic tripwire',
                             'breach_response': {   'tier1_pp': 5.0,
                                                    'tier1': 'one-question NET '
                                                             'breach: enumerate '
                                                             'every discordant '
                                                             'adversarial question '
                                                             '- both B-only wins '
                                                             'and C-only wins - '
                                                             "and diff each one's "
                                                             'Arm B vs Arm C '
                                                             'retrieved context, '
                                                             'recording all '
                                                             'findings in the '
                                                             'results. A net +5pp '
                                                             'does not imply '
                                                             'exactly one '
                                                             'differing question '
                                                             '(three C-only wins '
                                                             'against two B-only '
                                                             'wins nets the same '
                                                             '+5pp), so there is '
                                                             'no unique question '
                                                             'to diff and an '
                                                             'arbitrary pick could '
                                                             'miss the one '
                                                             'carrying arm leakage '
                                                             'while still '
                                                             'licensing M1/M3 to '
                                                             'be trusted. At N=20 '
                                                             'the discordance set '
                                                             'is small by '
                                                             'construction, so '
                                                             'full enumeration '
                                                             'stays a bounded '
                                                             'check, not an audit',
                                                    'tier2_pp': 10.0,
                                                    'tier2': 'two-or-more-question '
                                                             'breach: the full '
                                                             'leakage '
                                                             'investigation, '
                                                             'completed before '
                                                             'M1/M3 are trusted '
                                                             '(design doc S6 guard '
                                                             '4)',
                                                    'rationale': 'at N=20 one '
                                                                 'question is 5pp, '
                                                                 'so the smallest '
                                                                 'non-zero C-B '
                                                                 'already breaches '
                                                                 'the +3pp '
                                                                 'tripwire; under '
                                                                 'a true null it '
                                                                 'fires ~25-36% of '
                                                                 'the time. The '
                                                                 '+3pp tripwire is '
                                                                 'unchanged - only '
                                                                 'the depth of the '
                                                                 'mandated '
                                                                 'response is '
                                                                 'pinned (amended '
                                                                 '2026-08-14)'}}},
    'answering_model': {   'model': 'qwen3.8',
                           'api': 'chat-completions',
                           'endpoint': 'http://192.168.1.134:8000/v1',
                           'upstream_model': 'Qwen/Qwen3.8-27B-FP8',
                           'template_kwargs': {'enable_thinking': False},
                           'max_model_len': 131072,
                           'served_by': 'vLLM OpenAI-compatible server on GB10',
                           'reference_launch': 'vllm serve Qwen/Qwen3.8-27B-FP8 '
                                               '--served-model-name qwen3.8 --host '
                                               '0.0.0.0 --port 8000 '
                                               '--max-model-len 131072 '
                                               '--gpu-memory-utilization 0.5 '
                                               '--max-num-seqs 1 '
                                               '--enable-chunked-prefill '
                                               '--enable-prefix-caching',
                           'superseded_pin': 'gpt-oss:120b @ GB10 ollama '
                                             '192.168.1.134:11434'},
    'extractor_model': {   'model': 'qwen3.8',
                           'api': 'chat-completions',
                           'endpoint': 'http://192.168.1.134:8000/v1',
                           'upstream_model': 'Qwen/Qwen3.8-27B-FP8',
                           'template_kwargs': {'enable_thinking': False},
                           'max_model_len': 131072,
                           'served_by': 'vLLM OpenAI-compatible server on GB10',
                           'reference_launch': 'vllm serve Qwen/Qwen3.8-27B-FP8 '
                                               '--served-model-name qwen3.8 --host '
                                               '0.0.0.0 --port 8000 '
                                               '--max-model-len 131072 '
                                               '--gpu-memory-utilization 0.5 '
                                               '--max-num-seqs 1 '
                                               '--enable-chunked-prefill '
                                               '--enable-prefix-caching',
                           'superseded_pin': 'gpt-oss:120b @ GB10 ollama '
                                             '192.168.1.134:11434'},
    'model_fairness_constraint': 'answering model, extractor model, and retriever '
                                 'MUST be identical across arms A/B/C; the memory '
                                 'layer is the only independent variable',
    'judge_model': 'claude-opus-4-8 via claude -p (subscription), fallback '
                   'gemini-2.5-pro',
    'retriever': 'shared deterministic BM25 (stdlib), identical across arms',
    'temperature': 0,
    'seed': 20260717}

def _load_preregister() -> dict:
    return json.loads(PREREGISTER.read_text(encoding="utf-8"))


def test_preregister_and_design_doc_exist() -> None:
    assert PREREGISTER.is_file(), f"pre-registration not found at {PREREGISTER}"
    assert DESIGN_DOC.is_file(), f"design doc not found at {DESIGN_DOC}"


def test_preregister_carries_exactly_the_pinned_values() -> None:
    """Full-dict assertion over every pinned key -- spot-checks are forbidden."""
    actual = _load_preregister()

    recorded_hash = actual.pop("design_doc_sha256", None)
    assert recorded_hash is not None, "preregister.json is missing design_doc_sha256"

    # Same treatment for the M3 labels digest: verified by recomputation in
    # test_m3_labels_sha256_matches_recorded, never by comparison with a copy.
    recorded_labels_hash = actual["metrics"]["M3"].pop("labels_sha256", None)
    assert recorded_labels_hash is not None, (
        "preregister.json is missing metrics.M3.labels_sha256"
    )

    # Iterate the whole expected dict so a mismatch names the offending key...
    for key, value in EXPECTED.items():
        assert key in actual, f"preregister.json is missing pinned key: {key!r}"
        assert actual[key] == value, (
            f"pinned value drift for {key!r}:\n"
            f"  expected = {value!r}\n"
            f"  actual   = {actual[key]!r}"
        )
    # ...then assert deep equality so no extra or missing key escapes the check.
    assert actual == EXPECTED, (
        "preregister.json does not equal the pinned dict exactly "
        "(extra or missing keys once the sha256 is removed):\n"
        f"  expected keys = {sorted(EXPECTED)}\n"
        f"  actual keys   = {sorted(actual)}"
    )


def test_design_doc_sha256_matches_recorded() -> None:
    """Recompute the design-doc SHA-256 and assert it matches the recorded value.

    The doc is hashed after normalizing CRLF -> LF so the pin is checkout-line-ending
    independent: a Windows CRLF working tree and a Linux/CI LF checkout of the same
    committed content must hash identically.
    """
    recorded_hash = _load_preregister()["design_doc_sha256"]

    assert isinstance(recorded_hash, str) and len(recorded_hash) == 64, (
        f"design_doc_sha256 must be 64 hex chars, got {recorded_hash!r}"
    )
    assert recorded_hash == recorded_hash.lower(), "design_doc_sha256 must be lowercase hex"

    normalized = DESIGN_DOC.read_bytes().replace(b"\r\n", b"\n")
    computed = hashlib.sha256(normalized).hexdigest()
    assert computed == recorded_hash, (
        "design doc SHA-256 mismatch -- was the doc edited after pinning?\n"
        f"  recorded = {recorded_hash}\n"
        f"  computed = {computed}"
    )


def test_m3_labels_sha256_matches_recorded() -> None:
    """Recompute the M3 labels SHA-256 and assert it matches the recorded value.

    The labels file *is* M3's sample: its keys are the denominator and its values
    are what "contaminated" means. Pinning it by digest is what stops the metric
    being redefined after the fact by editing the data it scores. Hashed with the
    same CRLF -> LF normalization as the design doc, so the pin holds on a Windows
    CRLF working tree and a Linux LF checkout alike.
    """
    record = _load_preregister()["metrics"]["M3"]
    recorded_hash = record["labels_sha256"]
    labels_path = REPO_ROOT / record["labels_file"]

    assert labels_path.is_file(), f"pinned labels file not found at {labels_path}"
    assert isinstance(recorded_hash, str) and len(recorded_hash) == 64, (
        f"labels_sha256 must be 64 hex chars, got {recorded_hash!r}"
    )
    assert recorded_hash == recorded_hash.lower(), "labels_sha256 must be lowercase hex"

    normalized = labels_path.read_bytes().replace(b"\r\n", b"\n")
    computed = hashlib.sha256(normalized).hexdigest()
    assert computed == recorded_hash, (
        "M3 labels SHA-256 mismatch -- were the labels edited after pinning?\n"
        f"  recorded = {recorded_hash}\n"
        f"  computed = {computed}"
    )


def test_m3_denominator_is_consistent_with_the_labels_file() -> None:
    """N, the label keyset and the no-update exclusions must agree with each other.

    Three numbers in the pre-registration describe one sample; if they can drift
    apart, the recorded N stops meaning what the labels actually score.
    """
    record = _load_preregister()["metrics"]["M3"]
    labels = json.loads(
        (REPO_ROOT / record["labels_file"]).read_text(encoding="utf-8")
    )
    excluded = record["no_update_exclusions"]

    assert len(labels) == 72, "the labels file keeps every structural KU non-_abs id"
    assert sorted(excluded) == sorted(
        qid for qid, values in labels.items() if not values
    ), "the pinned no-update ids must be exactly the empty-label questions"
    assert record["N"] == len(labels) - len(excluded) == 66

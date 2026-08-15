"""Tests for the LongMemEval real-model execution layer.

The layer under test is the one that finally binds the pinned models — and the
one thing these tests must never do is *reach* them: the first real generation
from a pinned arm closes design doc §6.3's pre-registration amendment window, so
every path here runs against injected transports with sockets and the judge
process disabled.

Three groups:

* **pins** — the model identifiers, endpoints and transports are parsed out of
  ``preregister.json`` at run time. The parse is asserted against the *real*
  pinned strings, because a silent misparse would point the whole run at the
  wrong model while the results still claimed the pinned one.
* **clients** — request construction, strict UTF-8 decoding, and the two Windows
  subprocess failure modes that silently produce a scored-but-fabricated verdict
  if they are not caught (``rc=0`` with empty stdout, and a non-UTF-8 stream).
* **orchestration** — the full run over fixture questions: blind scoring order,
  resume-after-kill in both phases, durable rows, and the manifest's pin record.
"""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Sequence

import pytest

from benchmarks.longmemeval import clients, corpus, real_run
from benchmarks.longmemeval.arms import ARM_STORES
from benchmarks.longmemeval.pipeline import (
    JudgeVerdictError,
    ModelPin,
    blind_batch_order,
    pinned_seed,
    preregistered,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES_ROOT = _REPO_ROOT / "samples"

_PIN = ModelPin(model="stub-model", endpoint="http://stub.invalid:1", temperature=0.0, seed=7)
_CLI_PIN = clients.CliPin(
    pin=ModelPin(model="stub-judge", endpoint="cli:stub -p", temperature=0.0, seed=7),
    argv=("stub", "-p"),
    fallback_model="stub-fallback",
)


# --------------------------------------------------------------------------- #
# Pins: the pre-registration's prose is parsed, never re-declared              #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_server_pin_parses_the_real_pinned_answering_model() -> None:
    """The live pin must resolve to a model plus exactly one endpoint.

    Asserted against ``preregister.json`` itself rather than a fixture: the
    parser's whole job is reading *that* text, and a fixture-only test would stay
    green while the real pin became unreadable.
    """
    pin = clients.answering_pin()
    raw = str(preregistered("answering_model"))

    assert pin.model in raw
    assert pin.model.split("@")[0].strip() == pin.model
    assert pin.endpoint.startswith(clients.DEFAULT_SCHEME)
    assert pin.endpoint.rsplit("/", 1)[-1] in raw
    assert pin.temperature == float(preregistered("temperature"))
    assert pin.seed == pinned_seed()


@pytest.mark.unit
def test_extractor_and_answering_pins_are_read_independently() -> None:
    """Both are pinned to one model today; each is still read from its own key."""
    assert clients.extractor_pin().model == clients.answering_pin().model
    assert clients.extractor_pin().endpoint == clients.answering_pin().endpoint


@pytest.mark.unit
def test_judge_pin_parses_model_transport_and_fallback() -> None:
    cli_pin = clients.judge_pin()
    raw = str(preregistered("judge_model"))

    assert cli_pin.pin.model in raw
    assert cli_pin.argv, "the judge pin must name a command to run"
    assert cli_pin.pin.endpoint == "cli:" + " ".join(cli_pin.argv)
    assert cli_pin.fallback_model is not None
    assert cli_pin.fallback_model in raw
    # The parenthetical and the fallback clause must not leak into the command.
    assert not any("(" in part or "," in part for part in cli_pin.argv)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["model-with-no-endpoint", "model @ somewhere", "model @ a:1 b:2", "@ a:1"],
)
def test_server_pin_refuses_a_shape_it_cannot_read(value: str) -> None:
    """Zero or several endpoints is a stop, never a guess."""
    with pytest.raises(clients.PinParseError):
        clients.parse_server_pin(value, temperature=0.0, seed=1)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["model-with-no-transport", "model via (only)"])
def test_cli_pin_refuses_a_shape_it_cannot_read(value: str) -> None:
    with pytest.raises(clients.PinParseError):
        clients.parse_cli_pin(value, temperature=0.0, seed=1)


@pytest.mark.unit
def test_server_pin_keeps_an_explicit_scheme() -> None:
    pin = clients.parse_server_pin(
        "m @ https://host.example:8443", temperature=0.0, seed=1
    )
    assert pin.endpoint == "https://host.example:8443"


@pytest.mark.unit
def test_a_tagged_pin_never_matches_a_neighbouring_tag() -> None:
    """The tag is part of the snapshot's identity, so it is not fuzzy-matched."""
    assert clients.model_matches("m:120b", "m:120b")
    assert not clients.model_matches("m:120b", "m:20b")
    assert clients.model_matches("m", "m:latest")


# --------------------------------------------------------------------------- #
# The LAN chat client                                                          #
# --------------------------------------------------------------------------- #


def _transport(responses: Sequence[Any], record: list[tuple[str, dict]]):
    """A fake transport that records requests and replays canned responses."""
    queue = list(responses)

    def transport(url: str, payload: bytes, timeout: float) -> bytes:
        record.append((url, json.loads(payload) if payload else {}))
        nxt = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(nxt, Exception):
            raise nxt
        return nxt if isinstance(nxt, bytes) else json.dumps(nxt).encode("utf-8")

    return transport


@pytest.mark.unit
def test_chat_sends_the_pinned_model_and_knobs() -> None:
    """Temperature and seed travel on every request — §6 guard 2 is per-call."""
    seen: list[tuple[str, dict]] = []
    client = clients.LocalChatClient(
        pin=_PIN,
        transport=_transport([{"message": {"content": "hello"}}], seen),
    )

    assert client.chat([{"role": "user", "content": "hi"}]) == "hello"
    url, body = seen[0]
    assert url == _PIN.endpoint + clients.CHAT_PATH
    assert body["model"] == _PIN.model
    assert body["stream"] is False
    assert body["options"] == {"temperature": _PIN.temperature, "seed": _PIN.seed}
    assert body["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.unit
@pytest.mark.parametrize(
    "response",
    [
        {"message": {}},
        {"message": {"content": "   "}},
        {"error": "model not found"},
        {"not_a_message": 1},
        b"{not json",
        b'{"message": {"content": "\xff\xfe"}}',
    ],
)
def test_chat_refuses_to_invent_an_answer(response: Any) -> None:
    """A missing, empty or unreadable completion is an error, never an ``""``.

    An empty answer recorded as a real one enters a plumbing failure into M1 as a
    wrong answer, which is exactly the silent-corruption class this run cannot
    afford.
    """
    client = clients.LocalChatClient(pin=_PIN, transport=_transport([response], []))
    with pytest.raises(clients.LocalModelResponseError):
        client.chat([{"role": "user", "content": "hi"}])


@pytest.mark.unit
def test_chat_retries_transport_failures_then_succeeds() -> None:
    """A busy LAN endpoint must not end a multi-hour run on the first refusal."""
    seen: list[tuple[str, dict]] = []
    responses = [
        urllib.error.URLError("connection refused"),
        {"message": {"content": "recovered"}},
    ]
    client = clients.LocalChatClient(
        pin=_PIN, attempts=3, transport=_transport(responses, seen)
    )
    assert client.chat([{"role": "user", "content": "hi"}]) == "recovered"
    assert len(seen) == 2


@pytest.mark.unit
def test_chat_gives_up_after_the_attempt_budget() -> None:
    client = clients.LocalChatClient(
        pin=_PIN,
        attempts=2,
        transport=_transport([urllib.error.URLError("down")], []),
    )
    with pytest.raises(clients.LocalModelTransportError, match="2 attempt"):
        client.chat([{"role": "user", "content": "hi"}])


@pytest.mark.unit
def test_preflight_checks_the_model_inventory_without_generating() -> None:
    """Connectivity only: --preflight must not spend the run's first generation."""
    seen: list[tuple[str, dict]] = []
    client = clients.LocalChatClient(
        pin=_PIN,
        get_transport=_transport([{"models": [{"name": _PIN.model}]}], seen),
    )
    report = client.preflight()

    assert report["model_present"] is True
    assert [url for url, _ in seen] == [_PIN.endpoint + clients.TAGS_PATH]
    assert clients.CHAT_PATH not in seen[0][0]


@pytest.mark.unit
def test_preflight_reports_a_missing_model() -> None:
    client = clients.LocalChatClient(
        pin=_PIN,
        get_transport=_transport([{"models": [{"name": "something-else"}]}], []),
    )
    assert client.preflight()["model_present"] is False


# --------------------------------------------------------------------------- #
# The judge CLI                                                                #
# --------------------------------------------------------------------------- #


def _judge(
    results: Sequence[clients.ProcessResult] | clients.ProcessResult,
    record: list[tuple[list[str], bytes | None]] | None = None,
    **kwargs: Any,
) -> clients.JudgeClient:
    queue = list(results) if isinstance(results, (list, tuple)) else [results]
    calls = record if record is not None else []

    def runner(argv: Sequence[str], stdin: bytes | None, timeout: float):
        calls.append((list(argv), stdin))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return clients.JudgeClient(
        cli_pin=_CLI_PIN,
        runner=runner,
        resolver=lambda name: f"C:\\bin\\{name}.cmd",
        **kwargs,
    )


def _ok(stdout: bytes) -> clients.ProcessResult:
    return clients.ProcessResult(returncode=0, stdout=stdout, stderr=b"")


@pytest.mark.unit
def test_judge_builds_the_pinned_command_and_passes_the_prompt_on_stdin() -> None:
    """The resolved executable, the pinned model, and no arm label anywhere."""
    calls: list[tuple[list[str], bytes | None]] = []
    judge = _judge(_ok(b"CORRECT\n"), calls)

    assert judge.verdict("When?", "22:00", "22:00") is True
    argv, stdin = calls[0]
    assert argv[0] == "C:\\bin\\stub.cmd"
    assert argv[1:] == ["-p", "--model", _CLI_PIN.pin.model]
    assert stdin is not None
    prompt = stdin.decode("utf-8")
    assert "When?" in prompt and "22:00" in prompt
    # Design doc §6.1 guard 1: the arm never reaches the judge.
    for arm in ARM_STORES:
        assert f"arm {arm}" not in prompt.lower()
    assert "arm" not in prompt.lower().split("candidate answer")[0]


@pytest.mark.unit
def test_judge_can_pass_the_prompt_as_an_argument() -> None:
    """Selectable because which form the installed CLI accepts is an ops fact."""
    calls: list[tuple[list[str], bytes | None]] = []
    judge = _judge(_ok(b"INCORRECT"), calls, prompt_via=clients.PROMPT_VIA_ARGV)

    assert judge.verdict("q", "g", "c") is False
    argv, stdin = calls[0]
    assert stdin is None
    assert "Candidate answer: c" in argv[-1]


@pytest.mark.unit
def test_judge_decodes_stdout_as_strict_utf8() -> None:
    """The cp950 trap: a non-UTF-8 stream must fail loud, never be substituted.

    ``subprocess.run(text=True)`` would decode with the locale codec inside its
    reader thread on this platform; this client captures bytes precisely so the
    failure surfaces here instead of as a mangled or vanished verdict.
    """
    judge = _judge(_ok("CORRECT — 正確".encode("cp950")))
    with pytest.raises(clients.JudgeTransportError, match="not valid UTF-8"):
        judge.verdict("q", "g", "c")


@pytest.mark.unit
def test_judge_rejects_a_successful_run_that_wrote_nothing() -> None:
    """rc=0 with empty stdout is the documented silent-failure signature."""
    judge = _judge(_ok(b""))
    with pytest.raises(clients.JudgeTransportError, match="wrote nothing"):
        judge.verdict("q", "g", "c")


@pytest.mark.unit
def test_judge_reports_a_nonzero_exit() -> None:
    judge = _judge(clients.ProcessResult(returncode=1, stdout=b"", stderr=b"quota"))
    with pytest.raises(clients.JudgeTransportError, match="quota"):
        judge.verdict("q", "g", "c")


@pytest.mark.unit
@pytest.mark.parametrize(
    "stdout",
    [b"", b"\n \n", b"maybe", b"The answer looks right to me.", b"CORRECT-ish"],
)
def test_an_unparseable_verdict_never_defaults_to_incorrect(stdout: bytes) -> None:
    """Defaulting is not neutral: judge failures correlate with the arm judged.

    A long, hedged answer both derails the judge more often and comes from some
    arms more than others, so "unreadable means wrong" would push a systematic,
    arm-correlated error straight into M1's gate.
    """
    with pytest.raises((JudgeVerdictError, clients.JudgeTransportError)):
        _judge(_ok(stdout)).verdict("q", "g", "c")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        (b"CORRECT", True),
        (b"correct\n", True),
        (b"INCORRECT.", False),
        (b"Reasoning about the answer.\nINCORRECT\n", False),
    ],
)
def test_verdict_parsing_reads_the_final_line(stdout: bytes, expected: bool) -> None:
    assert _judge(_ok(stdout)).verdict("q", "g", "c") is expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired(cmd="stub", timeout=1.0),
        OSError("cannot execute"),
    ],
)
def test_a_hung_or_unlaunchable_judge_is_a_typed_transport_error(
    failure: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The judging loop's callers are written against the typed errors.

    A ``TimeoutExpired`` escaping the default runner would read as a harness
    crash mid-run rather than as the retryable transport failure it is.
    """

    def _raise(*args: Any, **kwargs: Any):
        raise failure

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(clients.JudgeTransportError):
        clients._subprocess_runner(["stub", "-p"], b"prompt", 1.0)


@pytest.mark.unit
def test_a_missing_judge_command_is_an_actionable_error() -> None:
    judge = clients.JudgeClient(
        cli_pin=_CLI_PIN,
        runner=lambda *args: pytest.fail("must not run a command it cannot find"),
        resolver=lambda name: None,
    )
    with pytest.raises(clients.JudgeUnavailableError, match="not found on PATH"):
        judge.verdict("q", "g", "c")


@pytest.mark.unit
def test_judge_preflight_only_asks_for_a_version() -> None:
    calls: list[tuple[list[str], bytes | None]] = []
    report = _judge(_ok(b"1.2.3\n"), calls).preflight()

    assert report["runs"] is True
    assert report["version"] == "1.2.3"
    assert report["fallback_model"] == _CLI_PIN.fallback_model
    assert calls[0][0][1:] == ["--version"]


@pytest.mark.unit
def test_the_pinned_fallback_judge_is_recorded_but_never_auto_swapped() -> None:
    """An automatic swap would judge one blind batch with two unrecorded models."""
    judge = _judge(clients.ProcessResult(returncode=1, stdout=b"", stderr=b"limit"))
    assert judge.fallback_model == _CLI_PIN.fallback_model
    with pytest.raises(clients.JudgeTransportError):
        judge.verdict("q", "g", "c")


# --------------------------------------------------------------------------- #
# Fixture corpus                                                               #
# --------------------------------------------------------------------------- #

_QUESTIONS = [
    ("ku-one", "ku", "What is my 5K personal best?", "22:00"),
    ("ku-two", "ku", "What is my resting heart rate?", "54"),
    ("ms-one", "ms", "Which city do I live in?", "Taipei"),
    ("adv-one", "adversarial", "What coffee do I prefer?", "flat white"),
]

# Two dated sessions per question so the shared linker has an update to detect on
# the knowledge-update pair: an older value, then a newer one on the same
# subject. Without a supersedes edge Arm C degenerates to Arm B (design doc §7.3)
# and the orchestration would be exercised on a corpus that cannot separate them.
_SESSIONS: dict[str, list[tuple[str, str, list[str]]]] = {
    "ku-one": [
        ("s1", "2023-01-05T09:00:00Z", ["my 5k personal best is 24:30"]),
        ("s2", "2023-06-05T09:00:00Z", ["my 5k personal best is 22:00"]),
    ],
    "ku-two": [
        ("s1", "2023-02-05T09:00:00Z", ["my resting heart rate is 61"]),
        ("s2", "2023-07-05T09:00:00Z", ["my resting heart rate is 54"]),
    ],
    "ms-one": [
        ("s1", "2023-03-05T09:00:00Z", ["i live in Taipei"]),
        ("s2", "2023-08-05T09:00:00Z", ["i live in Taipei"]),
    ],
    "adv-one": [
        ("s1", "2023-04-05T09:00:00Z", ["my favourite coffee is flat white"]),
        ("s2", "2023-09-05T09:00:00Z", ["i drink coffee every morning"]),
    ],
}


def _record(question_id: str, question: str, gold: str, qtype: str) -> dict:
    sessions = _SESSIONS[question_id]
    return {
        "question_id": question_id,
        "question_type": qtype,
        "question": question,
        "answer": gold,
        "question_date": "2023-10-01",
        "answer_session_ids": [sid for sid, _, _ in sessions],
        "haystack_session_ids": [sid for sid, _, _ in sessions],
        "haystack_dates": [date for _, date, _ in sessions],
        "haystack_sessions": [
            [{"role": "user", "content": line} for line in lines]
            for _, _, lines in sessions
        ],
    }


@pytest.fixture
def corpus_dir(tmp_path: Path) -> Path:
    """A tiny stand-in corpus. The real data directory is never read here."""
    directory = tmp_path / "data"
    directory.mkdir()
    records = [
        _record(qid, question, gold, "knowledge-update" if split == "ku" else split)
        for qid, split, question, gold in _QUESTIONS
    ]
    body = json.dumps(records, ensure_ascii=False)
    (directory / corpus.ORACLE_FILENAME).write_text(body, encoding="utf-8")
    (directory / corpus.S_CLEANED_FILENAME).write_text(body, encoding="utf-8")
    return directory


@pytest.fixture
def split_path(tmp_path: Path) -> Path:
    manifest = {
        "seed": corpus.SEED,
        "question_ids": {
            "ku": ["ku-one", "ku-two"],
            "ms": ["ms-one"],
            "adversarial": ["adv-one"],
        },
        "source_sha256": {corpus.ORACLE_FILENAME: "0" * 64},
    }
    path = tmp_path / "split.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class FakeChat:
    """A deterministic stand-in for the pinned LAN model.

    Extraction echoes the session lines, so the shared linker sees exactly the
    bodies the fixture wrote; answering echoes the top-ranked memory item, which
    is the same shape ``run.stub_answerer`` uses. Both are pure functions of the
    prompt, so any difference between arms comes from the memory layer.
    """

    def __init__(self, pin: ModelPin) -> None:
        self.pin = pin
        self.extract_calls = 0
        self.answer_calls = 0
        self.fail_after: int | None = None

    def chat(self, messages: Sequence[dict]) -> str:
        system, user = messages[0]["content"], messages[1]["content"]
        if system == clients.EXTRACT_SYSTEM_PROMPT:
            self.extract_calls += 1
            self._maybe_fail()
            return user.split("Session:\n", 1)[1]
        self.answer_calls += 1
        self._maybe_fail()
        block = user.split("Memory items:\n", 1)[1].split("\n\nQuestion:", 1)[0]
        first = block.split("\n")[0]
        return first.split(". ", 1)[1] if ". " in first else first

    def _maybe_fail(self) -> None:
        if self.fail_after is not None:
            if self.extract_calls + self.answer_calls > self.fail_after:
                raise RuntimeError("simulated interruption")


class FakeJudge:
    """A blind judge that records exactly what it was shown, in order."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str]] = []
        self.fail_after: int | None = None
        self.fallback_model = "stub-fallback"

    def verdict(self, question: str, gold: str, candidate_answer: str) -> bool:
        if self.fail_after is not None and len(self.seen) >= self.fail_after:
            raise clients.JudgeTransportError("simulated quota wall")
        self.seen.append((question, gold, candidate_answer))
        return gold.lower() in candidate_answer.lower()


def _config(tmp_path: Path, corpus_dir: Path, split_path: Path, **overrides: Any):
    settings: dict[str, Any] = {
        "out_dir": tmp_path / "run",
        "split": real_run.SPLIT_ALL,
        "haystack": real_run.HAYSTACK_ORACLE,
        "data_dir": corpus_dir,
        "samples_root": _SAMPLES_ROOT,
        "split_manifest_path": split_path,
        "resamples": 64,
    }
    settings.update(overrides)
    return real_run.RealRunConfig(**settings)


def _factory(created: list[FakeChat]):
    def factory(pin: ModelPin) -> FakeChat:
        client = FakeChat(pin)
        created.append(client)
        return client

    return factory


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_real_run_end_to_end_over_fixture_questions(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """Every arm answers every question, then one blind batch, then the metrics."""
    cfg = _config(tmp_path, corpus_dir, split_path)
    chats: list[FakeChat] = []
    judge = FakeJudge()

    metrics = real_run.execute(cfg, client_factory=_factory(chats), judge_client=judge)

    answers = real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME)
    assert len(answers) == len(_QUESTIONS) * len(ARM_STORES)
    assert {(row["question_id"], row["arm"]) for row in answers} == {
        (qid, arm) for qid, _, _, _ in _QUESTIONS for arm in ARM_STORES
    }

    verdicts = real_run.read_jsonl(cfg.out_dir / real_run.VERDICTS_NAME)
    assert len(verdicts) == len(_QUESTIONS) * len(ARM_STORES)
    assert len(judge.seen) == len(verdicts)

    assert metrics["counts"] == {"adversarial": 1, "ku": 2, "ms": 1}
    # M1 is computed over the knowledge-update slice only, and refuses a gate
    # verdict away from its pinned denominator.
    assert metrics["m1"]["n"] == 2
    assert metrics["m1"]["n_matches_pin"] is False
    assert metrics["m1"]["gate_verdict"] is None
    assert set(metrics["m2"]["f1"]) == set(ARM_STORES)
    assert metrics["m4"]["p95_ms"]["A"] >= 0.0
    assert metrics["ag"]["n"] == 1
    # The fixture's knowledge-update pair carries a genuine old -> new update, so
    # the shared linker must have found an edge; with zero, Arm C could not
    # differ from Arm B whatever the machinery does (design doc §7.3).
    assert metrics["linker"]["supersedes_edges"] >= 2

    stored = json.loads((cfg.out_dir / real_run.METRICS_NAME).read_text(encoding="utf-8"))
    assert stored["counts"] == metrics["counts"]


@pytest.mark.integration
def test_the_judge_sees_one_shuffled_batch_not_three_arm_runs(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """Design doc §6.1 guard 1: candidates are pooled and shuffled before scoring.

    An arm leaks through position even with no label attached, so a judge handed
    all of A, then all of B, then all of C could favour "the fancy one" from
    ordering alone.
    """
    cfg = _config(tmp_path, corpus_dir, split_path)
    judge = FakeJudge()
    real_run.execute(cfg, client_factory=_factory([]), judge_client=judge)

    specs = real_run.load_questions(
        split=cfg.split,
        limit=None,
        haystack=cfg.haystack,
        data_directory=corpus_dir,
        split_manifest=real_run.load_split(split_path),
    )
    order = blind_batch_order(sorted(ARM_STORES), len(specs), seed=pinned_seed())
    expected = [specs[slot.question_index].question for slot in order]

    assert [question for question, _, _ in judge.seen] == expected

    # ... and that is not the order inline per-arm judging would have produced.
    inline = [spec.question for spec in specs for _ in ARM_STORES]
    assert expected != inline


@pytest.mark.integration
def test_an_interrupted_answering_phase_resumes_without_re_answering(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """A run killed mid-answering redoes nothing it had already recorded."""
    cfg = _config(tmp_path, corpus_dir, split_path)

    def failing_factory(pin: ModelPin) -> FakeChat:
        client = FakeChat(pin)
        client.fail_after = 6
        return client

    with pytest.raises(RuntimeError, match="simulated interruption"):
        real_run.execute(cfg, client_factory=failing_factory, judge_client=FakeJudge())

    partial = real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME)
    assert 0 < len(partial) < len(_QUESTIONS) * len(ARM_STORES)
    done = {(row["question_id"], row["arm"]) for row in partial}
    extracted = len(real_run.read_jsonl(cfg.out_dir / real_run.EXTRACTIONS_NAME))
    assert extracted > 0

    resumed: list[FakeChat] = []
    real_run.execute(cfg, client_factory=_factory(resumed), judge_client=FakeJudge())

    rows = real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME)
    keys = [(row["question_id"], row["arm"]) for row in rows]
    assert len(keys) == len(set(keys)) == len(_QUESTIONS) * len(ARM_STORES)

    # The second pass paid for exactly the work that was missing and nothing
    # that was already on disk. The extraction half of that is a correctness
    # property, not an economy: a re-extracted session could come back different
    # and the three arms would stop seeing byte-identical claims.
    sessions = sum(len(_SESSIONS[qid]) for qid, _, _, _ in _QUESTIONS)
    assert sum(client.answer_calls for client in resumed) == len(keys) - len(done)
    assert sum(client.extract_calls for client in resumed) == sessions - extracted

    session_ids = [
        row["session_id"]
        for row in real_run.read_jsonl(cfg.out_dir / real_run.EXTRACTIONS_NAME)
    ]
    assert len(session_ids) == len(set(session_ids)) == sessions


@pytest.mark.integration
def test_an_interrupted_judging_phase_resumes_in_the_pinned_order(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """The judge phase resumes at its position in the shuffle, not at the start."""
    cfg = _config(tmp_path, corpus_dir, split_path)
    first = FakeJudge()
    first.fail_after = 5

    with pytest.raises(clients.JudgeTransportError):
        real_run.execute(cfg, client_factory=_factory([]), judge_client=first)

    partial = real_run.read_jsonl(cfg.out_dir / real_run.VERDICTS_NAME)
    assert len(partial) == 5

    second = FakeJudge()
    real_run.execute(cfg, client_factory=_factory([]), judge_client=second)

    rows = real_run.read_jsonl(cfg.out_dir / real_run.VERDICTS_NAME)
    keys = [(row["arm"], row["question_id"]) for row in rows]
    assert len(keys) == len(set(keys)) == len(_QUESTIONS) * len(ARM_STORES)
    assert len(second.seen) == len(keys) - 5
    # Positions are contiguous in the pinned shuffle: the resume continued the
    # batch rather than restarting or reshuffling it.
    assert sorted(row["batch_position"] for row in rows) == list(range(len(keys)))


@pytest.mark.integration
def test_the_manifest_records_the_pins_the_answers_were_produced_under(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    cfg = _config(tmp_path, corpus_dir, split_path)
    real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())

    manifest = json.loads(
        (cfg.out_dir / real_run.MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert set(manifest["pins"]) == {"extractor", "answering", "judge"}
    assert manifest["pins"]["answering"]["model"] == clients.answering_pin().model
    assert manifest["pins"]["judge"]["model"] == clients.judge_pin().pin.model
    assert manifest["pins"]["answering"]["seed"] == pinned_seed()
    assert manifest["haystack"] == real_run.HAYSTACK_ORACLE
    assert manifest["question_count"] == len(_QUESTIONS)
    assert manifest["completed_at"] is not None
    assert manifest["design_doc_sha256"] == preregistered("design_doc_sha256")

    # Every answer row carries the same record, so a row can always be attributed.
    for row in real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME):
        assert row["pins"] == manifest["pins"]


@pytest.mark.integration
def test_resuming_a_different_slice_in_one_directory_is_refused(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """Two slices in one output directory would interleave two experiments."""
    cfg = _config(tmp_path, corpus_dir, split_path)
    real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())

    narrower = _config(tmp_path, corpus_dir, split_path, split="ku")
    with pytest.raises(real_run.RunManifestMismatchError, match="questions_sha256"):
        real_run.execute(
            narrower, client_factory=_factory([]), judge_client=FakeJudge()
        )


@pytest.mark.integration
def test_the_real_run_opens_no_socket_and_spawns_only_git(
    tmp_path: Path, corpus_dir: Path, split_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole orchestration runs with every real transport disabled.

    The one process the run is allowed to spawn is ``git``, for the commit sha
    the manifest records; the judge must arrive through the injected client.
    """

    def _boom(*args: Any, **kwargs: Any):
        raise RuntimeError("network call attempted inside the real run")

    spawned: list[list[str]] = []

    def _spy(argv, *args: Any, **kwargs: Any):
        spawned.append(list(argv))
        if list(argv)[0] != "git":
            raise RuntimeError(f"unexpected subprocess: {argv}")
        return types.SimpleNamespace(returncode=0, stdout=b"sha\n", stderr=b"")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", _boom, raising=False)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", _boom, raising=False)
    monkeypatch.setattr(subprocess, "run", _spy)

    cfg = _config(tmp_path, corpus_dir, split_path)
    metrics = real_run.execute(
        cfg, client_factory=_factory([]), judge_client=FakeJudge()
    )

    assert metrics["m1"] is not None
    assert all(argv[0] == "git" for argv in spawned)


@pytest.mark.integration
def test_all_three_arms_see_byte_identical_claims(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """The fairness constraint: only the memory layer may differ across arms.

    The extractor is model-backed here, and a model asked three times can answer
    three ways, so the durable memo is a correctness mechanism before it is an
    economy.
    """
    cfg = _config(tmp_path, corpus_dir, split_path)
    chats: list[FakeChat] = []
    real_run.execute(cfg, client_factory=_factory(chats), judge_client=FakeJudge())

    sessions = sum(len(_SESSIONS[qid]) for qid, _, _, _ in _QUESTIONS)
    assert sum(client.extract_calls for client in chats) == sessions

    extractions = real_run.read_jsonl(cfg.out_dir / real_run.EXTRACTIONS_NAME)
    assert len({row["session_id"] for row in extractions}) == sessions


@pytest.mark.integration
def test_a_resumed_run_produces_the_same_claims_as_an_uninterrupted_one(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """An interruption must not change what the arms were compared over.

    The shared linker is rebuilt from scratch on resume — a question whose arms
    were only partly answered is re-linked — so this asserts the rebuild lands on
    byte-identical claims. If it did not, a resumed run would compare its arms
    over a different memory than an uninterrupted one, and the interruption would
    become a silent independent variable.
    """
    clean = _config(tmp_path / "clean", corpus_dir, split_path)
    real_run.execute(clean, client_factory=_factory([]), judge_client=FakeJudge())

    resumed = _config(tmp_path / "resumed", corpus_dir, split_path)

    def failing_factory(pin: ModelPin) -> FakeChat:
        client = FakeChat(pin)
        client.fail_after = 6
        return client

    with pytest.raises(RuntimeError, match="simulated interruption"):
        real_run.execute(
            resumed, client_factory=failing_factory, judge_client=FakeJudge()
        )
    real_run.execute(resumed, client_factory=_factory([]), judge_client=FakeJudge())

    def claims_by_question(cfg: real_run.RealRunConfig) -> dict[str, Any]:
        return {
            row["question_id"]: (row["claims"], row["linker"])
            for row in real_run.read_jsonl(cfg.out_dir / real_run.CLAIMS_NAME)
        }

    assert claims_by_question(resumed) == claims_by_question(clean)

    def predictions(cfg: real_run.RealRunConfig) -> dict[tuple[str, str], str]:
        return {
            (row["question_id"], row["arm"]): row["prediction"]
            for row in real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME)
        }

    assert predictions(resumed) == predictions(clean)


@pytest.mark.integration
def test_arm_c_suppresses_a_superseded_value_the_other_arms_keep(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """The mechanism under test, visible end to end through the real orchestration.

    The fixture's knowledge-update question states an old value and then a newer
    one. Arms A and B retrieve both and answer from the stale claim; Arm C's
    supersession suppression removes it, so only the current value reaches the
    answering model. This is the M1/M3 effect the benchmark exists to measure, so
    a run where all three arms retrieved identically would mean the harness was
    exercising nothing.
    """
    cfg = _config(tmp_path, corpus_dir, split_path)
    real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())

    rows = {
        row["arm"]: row
        for row in real_run.read_jsonl(cfg.out_dir / real_run.ANSWERS_NAME)
        if row["question_id"] == "ku-one"
    }

    assert "24:30" in rows["A"]["prediction"]
    assert "24:30" in rows["B"]["prediction"]
    assert "22:00" in rows["C"]["prediction"]
    assert len(rows["C"]["retrieved_ids"]) < len(rows["A"]["retrieved_ids"])


@pytest.mark.integration
def test_a_verdict_recorded_against_another_payload_is_refused(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """The replay pass proves the verdict stream matches the pinned blind order."""
    cfg = _config(tmp_path, corpus_dir, split_path)
    real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())

    path = cfg.out_dir / real_run.VERDICTS_NAME
    rows = real_run.read_jsonl(path)
    rows[0]["payload_sha256"] = "0" * 64
    path.write_bytes(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode("utf-8")
    )

    with pytest.raises(real_run.VerdictReplayError, match="different payload"):
        real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())


@pytest.mark.integration
def test_judging_refuses_an_incomplete_answer_set(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """No arm may be judged on a subset of the questions the others answered.

    Driven straight at :func:`judge_blind`, because ``execute`` re-answers any
    missing pair before judging: the guard exists for the case where the answers
    file was truncated or hand-edited between the two phases, which is exactly
    what this reproduces.
    """
    cfg = _config(tmp_path, corpus_dir, split_path)
    real_run.execute(cfg, client_factory=_factory([]), judge_client=FakeJudge())

    specs = real_run.load_questions(
        split=cfg.split,
        limit=None,
        haystack=cfg.haystack,
        data_directory=corpus_dir,
        split_manifest=real_run.load_split(split_path),
    )
    phase = real_run.load_answer_phase(cfg.out_dir)
    phase.rows.pop((specs[0].question_id, "A"))
    (cfg.out_dir / real_run.VERDICTS_NAME).unlink()

    with pytest.raises(real_run.MissingAnswerError, match="blind batch is incomplete"):
        real_run.judge_blind(
            specs,
            cfg,
            phase=phase,
            judge_client=FakeJudge(),
            seed=pinned_seed(),
        )


# --------------------------------------------------------------------------- #
# Slicing, durability and the pinned statistics                                #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_a_limited_run_is_a_prefix_of_the_full_one(split_path: Path) -> None:
    manifest = real_run.load_split(split_path)
    full = real_run.selected_question_ids(manifest, real_run.SPLIT_ALL, None)
    assert real_run.selected_question_ids(manifest, real_run.SPLIT_ALL, 2) == full[:2]
    assert real_run.selected_question_ids(manifest, "adv", None) == [
        ("adv-one", "adversarial")
    ]


@pytest.mark.unit
def test_read_jsonl_tolerates_one_torn_final_row(tmp_path: Path) -> None:
    """A run killed mid-write loses that row's work, never the file."""
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"a": 1}\n{"b": 2}\n{"c": ')
    assert real_run.read_jsonl(path) == [{"a": 1}, {"b": 2}]


@pytest.mark.unit
def test_a_corrupt_row_in_the_middle_is_not_skipped(tmp_path: Path) -> None:
    path = tmp_path / "rows.jsonl"
    path.write_bytes(b'{"a": 1}\n{"b": \n{"c": 3}\n')
    with pytest.raises(json.JSONDecodeError):
        real_run.read_jsonl(path)


@pytest.mark.unit
def test_the_pinned_sign_test_reproduces_the_pre_registration_example() -> None:
    """``b = 5, c = 0`` must give ``p = 0.0625`` — the counterexample in the pin.

    ``preregister.json``'s M3 amendment records that worked example as the reason
    the INCONCLUSIVE rule keys on paired discordances rather than a marginal
    floor, so reproducing it is a direct check on the pinned statistic.
    """
    assert real_run.sign_test_p(5, 0) == pytest.approx(0.0625)
    assert real_run.sign_test_p(0, 0) == 1.0
    assert real_run.sign_test_p(3, 3) == 1.0
    assert real_run.sign_test_p(10, 0) == pytest.approx(2 / 1024)


@pytest.mark.unit
def test_the_adversarial_tripwire_enumerates_every_discordant_question() -> None:
    """A net advantage does not imply one differing question (pinned Tier 1)."""
    verdicts = {
        "B": [True, True, False, False, False],
        "C": [False, False, True, True, True],
    }
    report = real_run.adversarial_diagnostic(
        verdicts, [0, 1, 2, 3, 4], list("vwxyz"), real_run.PREREGISTER_PATH
    )

    assert report["delta_pp"] == pytest.approx(20.0)
    assert report["response_tier"] == "tier2"
    assert len(report["discordant"]) == 5
    assert [item["winner"] for item in report["discordant"]] == list("BBCCC")


@pytest.mark.unit
def test_the_adversarial_tiers_come_from_the_pre_registration() -> None:
    """The thresholds are read from the pin, never re-declared here."""
    report = real_run.adversarial_diagnostic(
        {"B": [True] * 20, "C": [True] * 20},
        list(range(20)),
        [str(index) for index in range(20)],
        real_run.PREREGISTER_PATH,
    )
    pinned = json.loads(real_run.PREREGISTER_PATH.read_text(encoding="utf-8"))
    response = pinned["metrics"]["AG"]["breach_response"]

    assert report["tier1_pp"] == response["tier1_pp"]
    assert report["tier2_pp"] == response["tier2_pp"]
    assert report["response_tier"] == "none"
    assert report["discordant"] == []


@pytest.mark.unit
def test_m3_is_reported_as_not_computed_rather_than_zero(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """A missing label source must never read as "no contamination"."""
    cfg = _config(tmp_path, corpus_dir, split_path)
    assert cfg.m3_labels is None
    assert real_run.load_m3_labels(None) == {}


@pytest.mark.integration
def test_m3_is_scored_when_stale_value_labels_are_supplied(
    tmp_path: Path, corpus_dir: Path, split_path: Path
) -> None:
    """With labels in hand the pinned readability test is reported alongside."""
    labels = tmp_path / "m3.json"
    labels.write_text(json.dumps({"ku-one": ["24:30"]}), encoding="utf-8")
    cfg = _config(tmp_path, corpus_dir, split_path, m3_labels=labels)

    metrics = real_run.execute(
        cfg, client_factory=_factory([]), judge_client=FakeJudge()
    )

    assert set(metrics["m3"]["rate"]) == set(ARM_STORES)
    readability = metrics["m3"]["readability"]
    assert readability["n"] == readability["b_a_only"] + readability["c_c_only"]
    assert 0.0 <= readability["p_value"] <= 1.0
    assert metrics["m3"]["labels_source"] == str(labels)


@pytest.mark.unit
def test_the_haystack_choice_selects_evidence_or_full_sessions(
    corpus_dir: Path,
) -> None:
    """§3.4's two corpus roles are both reachable and visibly different."""
    record = _record("ku-one", "q", "a", "knowledge-update")
    record["answer_session_ids"] = ["s2"]

    assert len(real_run.build_sessions(record, evidence_only=True)) == 1
    assert len(real_run.build_sessions(record, evidence_only=False)) == 2


@pytest.mark.unit
def test_the_run_refuses_an_unknown_split_or_haystack(split_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown split"):
        real_run.selected_question_ids(real_run.load_split(split_path), "nope", None)
    with pytest.raises(ValueError, match="unknown haystack"):
        real_run.load_questions(
            split="ku",
            limit=None,
            haystack="nope",
            data_directory=Path("."),
            split_manifest={},
        )


@pytest.mark.unit
def test_a_pins_only_config_cannot_run_a_stage() -> None:
    """It carries the record scoring needs and nothing that could generate."""
    config = real_run.pins_config(
        {
            "answering": _PIN,
            "extractor": _PIN,
            "judge": _CLI_PIN.pin,
        }
    )
    assert set(config.pins_record()) == {"extractor", "answering", "judge"}
    with pytest.raises(AssertionError, match="judge_blind"):
        config.judge.call("q", "g", "c", pin=_CLI_PIN.pin)
    with pytest.raises(AssertionError, match="RealExtractor"):
        config.extractor.call(None, pin=_PIN)


@pytest.mark.unit
def test_the_judge_prompt_mode_is_a_run_setting_not_a_code_edit() -> None:
    """Which form the installed CLI accepts is discovered on the driver's box.

    It cannot be verified from here — no real judgement may be made before the
    run — so the choice has to be reachable from the command line rather than
    require editing the harness mid-run.
    """
    assert real_run.RealRunConfig().judge_prompt_via == clients.PROMPT_VIA_STDIN
    assert set(clients.PROMPT_VIA_CHOICES) == {"stdin", "argv"}
    with pytest.raises(ValueError, match="prompt_via"):
        clients.JudgeClient(cli_pin=_CLI_PIN, prompt_via="telepathy")


@pytest.mark.integration
def test_preflight_reports_every_stage_without_generating(tmp_path: Path) -> None:
    """--preflight touches the inventory and a version, never a completion."""
    seen: list[tuple[str, dict]] = []

    def factory(pin: ModelPin) -> clients.LocalChatClient:
        return clients.LocalChatClient(
            pin=pin,
            get_transport=_transport([{"models": [{"name": pin.model}]}], seen),
            transport=lambda *args: pytest.fail("preflight must not generate"),
        )

    report = real_run.preflight(
        client_factory=factory, judge_client=_judge(_ok(b"1.0\n"))
    )

    assert report["ready"] is True
    assert report["errors"] == []
    assert all(url.endswith(clients.TAGS_PATH) for url, _ in seen)


@pytest.mark.integration
def test_preflight_reports_failures_instead_of_raising() -> None:
    """A preflight is a report; it must not die on the first unreachable stage."""

    def factory(pin: ModelPin) -> clients.LocalChatClient:
        return clients.LocalChatClient(
            pin=pin,
            get_transport=_transport([urllib.error.URLError("refused")], []),
        )

    report = real_run.preflight(
        client_factory=factory,
        judge_client=clients.JudgeClient(
            cli_pin=_CLI_PIN, runner=lambda *args: _ok(b""), resolver=lambda name: None
        ),
    )

    assert report["ready"] is False
    assert len(report["errors"]) == 3

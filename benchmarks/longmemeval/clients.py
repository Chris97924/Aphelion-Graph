"""Real-model stage clients for the LongMemEval execution run.

:mod:`benchmarks.longmemeval.pipeline` deliberately ships an *injection surface*
and no model identity: every model-backed stage resolves through a
:class:`~benchmarks.longmemeval.pipeline.StageBinding`, and an unpinned stage
raises :class:`~benchmarks.longmemeval.pipeline.UnpinnedStageError` rather than
inventing a model. This module is the other half — the concrete clients that
actually reach the pinned models — and it keeps the same discipline: **every**
model identifier, endpoint, temperature and seed is read out of
``preregister.json`` at call time. Nothing here carries a model name, a host, or
a port, which is what ``tests/test_benchmarks_execution.py``'s
``test_no_hardcoded_model_or_endpoint_defaults_in_the_package`` enforces.

Two transports, because the pre-registration names two very different ones:

* the **answering** and **extractor** stages share one model served over HTTP by
  a local inference server on the LAN (§5.2). :class:`LocalChatClient` speaks its
  chat API with :mod:`urllib.request`.
* the **judge** stage is a subscription CLI invoked as a subprocess (§5.2).
  :class:`JudgeClient` runs it and parses one strict verdict token.

Both clients take an injectable transport so the whole path is exercisable
offline: the tests drive real request construction, real response parsing and
real error handling without opening a socket or spawning a process.

Pure stdlib.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from benchmarks.longmemeval.pipeline import (
    PREREGISTER_PATH,
    Claim,
    JudgeVerdictError,
    ModelPin,
    pinned_seed,
    preregistered,
)


# ---------------------------------------------------------------------------
# Reading the pins: prose in, structure out
# ---------------------------------------------------------------------------

# ``preregister.json`` records its model pins as frozen *prose* — a human
# sentence naming the model, where it is served, and what stands in if it is
# unavailable. It is the pre-registration record and may not be reshaped
# (design doc §6.3), so the harness parses it instead. Each parser below is
# strict and raises :class:`PinParseError` on a shape it does not recognise:
# a pin that cannot be read is a stop, never a guess, because guessing would
# point a multi-hour run at a model the pre-registration never named.

# A network authority as the pins record it: ``host:port``, no scheme.
_AUTHORITY_RE = re.compile(r"^[A-Za-z0-9._-]+:\d{1,5}$")

# The fallback model named after the primary one in a CLI-transport pin.
_FALLBACK_RE = re.compile(r"\bfallback\s+([^\s,;()]+)", re.IGNORECASE)

# The pins record a bare ``host:port`` for the LAN server, so the scheme is
# supplied here. Plain HTTP, because the pinned endpoint is a private-network
# address with no TLS in the pre-registration; a pin that ever carries its own
# scheme is used verbatim instead (see :func:`parse_server_pin`).
DEFAULT_SCHEME = "http://"

# Separator between the model identity and its transport in a CLI pin.
_VIA = " via "


class PinParseError(ValueError):
    """A pinned model string was not the shape this module knows how to read.

    Sibling of :class:`~benchmarks.longmemeval.pipeline.GatePinError`, and for
    the same reason: ``preregister.json`` is the only source for what runs, so an
    unreadable pin must stop the run rather than fall back to a default. The
    message always quotes the offending text so the maintainer can see whether
    the pin was amended or the parser is stale.
    """


def _pin_knobs(path: Path = PREREGISTER_PATH) -> tuple[float, int]:
    """The decoding knobs every stage shares: pinned temperature and seed."""
    return float(preregistered("temperature", path)), pinned_seed(path)


def parse_server_pin(
    value: str, *, temperature: float, seed: int
) -> ModelPin:
    """Read a ``"<model> @ <where it is served> <host:port>"`` pin.

    The model identifier is everything left of the ``@``; the endpoint is the one
    ``host:port`` token to its right. Scanning for the authority rather than
    taking a fixed position is what lets the prose carry human context (which
    machine, which server) without the parser caring — while still refusing a pin
    that names zero or several endpoints, which would make "where did this run"
    ambiguous in the results.
    """
    model, separator, remainder = value.partition("@")
    if not separator or not model.strip():
        raise PinParseError(
            f"pinned model {value!r} is not of the form '<model> @ <host:port>'. "
            "This parser will not guess which half is the model identifier."
        )

    endpoints = [
        word if "://" in word else DEFAULT_SCHEME + word
        for word in remainder.split()
        if "://" in word or _AUTHORITY_RE.match(word)
    ]
    if len(endpoints) != 1:
        raise PinParseError(
            f"pinned model {value!r} names {len(endpoints)} endpoints "
            f"({endpoints}); exactly one 'host:port' is required so the results "
            "can record where the answers came from."
        )

    return ModelPin(
        model=model.strip(),
        endpoint=endpoints[0],
        temperature=temperature,
        seed=seed,
    )


@dataclass(frozen=True)
class CliPin:
    """A model reached by running a command, plus its pre-registered fallback.

    ``pin`` is what the results record; ``argv`` is the command prefix the pin's
    prose named ("<tool> <flag>"), which :class:`JudgeClient` extends with the
    model selector. ``fallback_model`` is carried but never used automatically —
    see :class:`JudgeClient` for why an automatic swap is refused.
    """

    pin: ModelPin
    argv: tuple[str, ...]
    fallback_model: str | None


def parse_cli_pin(value: str, *, temperature: float, seed: int) -> CliPin:
    """Read a ``"<model> via <command> (...), fallback <model>"`` pin.

    The recorded endpoint is ``cli:<command>``: a CLI-served model has no URL, and
    recording an empty endpoint would make two runs against the same model name
    through different transports indistinguishable in the results.
    """
    model, separator, remainder = value.partition(_VIA)
    if not separator or not model.strip():
        raise PinParseError(
            f"pinned model {value!r} is not of the form "
            f"'<model>{_VIA}<command> ...'. This parser will not guess how the "
            "model is reached."
        )

    # The transport is the command up to the first parenthetical or clause
    # separator, so "(subscription)" and ", fallback ..." stay out of argv.
    transport = remainder.split("(")[0].split(",")[0].strip()
    argv = tuple(shlex.split(transport))
    if not argv:
        raise PinParseError(
            f"pinned model {value!r} names no command to run after "
            f"{_VIA.strip()!r}."
        )

    fallback = _FALLBACK_RE.search(remainder)
    return CliPin(
        pin=ModelPin(
            model=model.strip(),
            endpoint=f"cli:{transport}",
            temperature=temperature,
            seed=seed,
        ),
        argv=argv,
        fallback_model=fallback.group(1) if fallback else None,
    )


def answering_pin(path: Path = PREREGISTER_PATH) -> ModelPin:
    """The pinned answering model (design doc §5.2)."""
    temperature, seed = _pin_knobs(path)
    return parse_server_pin(
        str(preregistered("answering_model", path)),
        temperature=temperature,
        seed=seed,
    )


def extractor_pin(path: Path = PREREGISTER_PATH) -> ModelPin:
    """The pinned extractor model (design doc §5.2).

    Read separately from :func:`answering_pin` even though the pre-registration
    currently names the same model for both: the fairness constraint is that each
    stage's model is identical *across arms*, not that the two stages share one
    model, and a run must record what each stage actually ran.
    """
    temperature, seed = _pin_knobs(path)
    return parse_server_pin(
        str(preregistered("extractor_model", path)),
        temperature=temperature,
        seed=seed,
    )


def judge_pin(path: Path = PREREGISTER_PATH) -> CliPin:
    """The pinned judge model and the command that reaches it (design doc §5.2)."""
    temperature, seed = _pin_knobs(path)
    return parse_cli_pin(
        str(preregistered("judge_model", path)),
        temperature=temperature,
        seed=seed,
    )


# ---------------------------------------------------------------------------
# The LAN inference server: answering + extraction
# ---------------------------------------------------------------------------

# The server's chat completion path. ``/api/chat`` rather than ``/api/generate``
# because the pinned answering model is a reasoning model that emits its analysis
# on a separate channel: the chat endpoint applies the model's own chat template
# and returns the final answer in ``message.content`` with the reasoning split
# out, whereas a raw-prompt generate call would either hand back the analysis
# inline or require this harness to reproduce the template itself. It also gives
# the system/user role split the fixed rubrics below are written against.
CHAT_PATH = "/api/chat"

# The model-inventory path, used by --preflight to prove the pinned model is
# actually loaded before a multi-hour run starts.
TAGS_PATH = "/api/tags"

# A 120B-class model on a LAN box answers in seconds, but a cold load is minutes.
# Generous rather than tight: a timeout here costs a retry of real model work.
DEFAULT_TIMEOUT_SECONDS = 600.0

# Transport attempts per request. A run spanning hours over a LAN endpoint will
# meet transient refusals; retrying transport failures keeps the run alive
# without touching determinism, because a retry re-sends a byte-identical request
# at temperature 0 under the pinned seed. Response-shape failures are NOT retried
# (see :meth:`LocalChatClient.chat`) — those are real answers this harness
# refuses to interpret, and repeating them would only hide them.
DEFAULT_ATTEMPTS = 3

# A transport takes (url, request body, timeout) and returns the raw response
# bytes. Injectable so tests exercise request construction and response parsing
# without a socket.
Transport = Callable[[str, bytes, float], bytes]


class LocalModelError(RuntimeError):
    """Base class for every failure reaching the pinned LAN model."""


class LocalModelTransportError(LocalModelError):
    """The request never produced a response this harness could read.

    Retried up to :data:`DEFAULT_ATTEMPTS` times before it surfaces, because the
    cause is usually a busy or restarting server rather than a bad request.
    """


class LocalModelResponseError(LocalModelError):
    """The server answered, but not with something usable as a stage result.

    Deliberately **not** retried and never defaulted to an empty string: a
    missing or empty completion on a reasoning model usually means the output
    budget was spent on the analysis channel, and silently recording "" would
    enter a plumbing failure into the results as a wrong answer.
    """


def model_matches(pinned: str, available: str) -> bool:
    """Does a model the server lists satisfy the pinned identifier?

    Exact match, or — when the pin names no ``:tag`` — any tag of that model.
    A *tagged* pin never matches a different tag: the tag is part of the model
    snapshot's identity, and quietly accepting a neighbouring one would let a run
    record a model it did not use.
    """
    if pinned == available:
        return True
    if ":" in pinned:
        return False
    return available.split(":", 1)[0] == pinned


def _urlopen_transport(url: str, payload: bytes, timeout: float) -> bytes:
    """POST ``payload`` as JSON and return the raw response body."""
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _urlget_transport(url: str, payload: bytes, timeout: float) -> bytes:
    """GET ``url`` and return the raw response body. ``payload`` is ignored."""
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


@dataclass(frozen=True)
class LocalChatClient:
    """Chat completions from the pinned LAN model, at the pinned knobs.

    ``pin`` supplies the model id, the base endpoint, the temperature and the
    seed — all four read from ``preregister.json`` — so a client cannot be built
    that runs something other than what the results will claim.
    """

    pin: ModelPin
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    attempts: int = DEFAULT_ATTEMPTS
    transport: Transport = _urlopen_transport
    get_transport: Transport = _urlget_transport

    def _url(self, path: str) -> str:
        return self.pin.endpoint.rstrip("/") + path

    def _request(self, transport: Transport, url: str, payload: bytes) -> Any:
        """Send one request with bounded retries and decode its JSON body.

        The body is decoded as **strict** UTF-8. ``errors="replace"`` is refused
        throughout this module: a replacement character inside a model's answer
        is indistinguishable from one the model actually wrote, so a decode
        failure must stop the row rather than corrupt it.
        """
        attempts = max(1, self.attempts)
        last: Exception | None = None
        raw: bytes | None = None
        for _ in range(attempts):
            try:
                raw = transport(url, payload, self.timeout_seconds)
                break
            # HTTPError and URLError are both OSError subclasses, so this one
            # clause covers refused connections, timeouts and error statuses
            # alike — every failure mode where re-sending an identical request is
            # the right response.
            except OSError as exc:
                last = exc
        if raw is None:
            raise LocalModelTransportError(
                f"{url}: {attempts} attempt(s) failed; last error: {last}"
            ) from last

        try:
            return json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise LocalModelResponseError(
                f"{url}: response body is not valid UTF-8 ({exc}). It is not "
                "decoded with errors='replace' on purpose — a substituted "
                "character inside a model answer would be silent corruption."
            ) from exc
        except json.JSONDecodeError as exc:
            raise LocalModelResponseError(
                f"{url}: response body is not JSON ({exc})."
            ) from exc

    def chat(self, messages: Sequence[Mapping[str, str]]) -> str:
        """Return the assistant's final content for ``messages``.

        ``stream`` is off so one request yields one complete body, and the pinned
        temperature and seed travel in ``options`` — the two knobs design doc §6
        guard 2 requires every generation to run under.
        """
        payload = json.dumps(
            {
                "model": self.pin.model,
                "messages": list(messages),
                "stream": False,
                "options": {
                    "temperature": self.pin.temperature,
                    "seed": self.pin.seed,
                },
            }
        ).encode("utf-8")

        body = self._request(self.transport, self._url(CHAT_PATH), payload)
        if not isinstance(body, dict):
            raise LocalModelResponseError(
                f"expected a JSON object from {CHAT_PATH}, got "
                f"{type(body).__name__}"
            )
        if body.get("error"):
            raise LocalModelResponseError(f"{CHAT_PATH} reported: {body['error']!r}")

        message = body.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LocalModelResponseError(
                f"{CHAT_PATH} returned no 'message.content' string (keys: "
                f"{sorted(body)}). This harness will not substitute an empty "
                "answer for a missing one."
            )
        if not content.strip():
            raise LocalModelResponseError(
                f"{CHAT_PATH} returned an empty 'message.content' for model "
                f"{self.pin.model!r}. On a reasoning model this usually means the "
                "output budget was spent on the analysis channel; it is raised "
                "rather than recorded, because an empty answer scored as wrong is "
                "a plumbing failure entering the results as a measurement."
            )
        return content

    def available_models(self) -> list[str]:
        """Every model the server currently reports, sorted."""
        body = self._request(self.get_transport, self._url(TAGS_PATH), b"")
        if not isinstance(body, dict) or not isinstance(body.get("models"), list):
            raise LocalModelResponseError(
                f"expected {{'models': [...]}} from {TAGS_PATH}, got "
                f"{type(body).__name__}"
            )
        names: list[str] = []
        for entry in body["models"]:
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("model")
                if isinstance(name, str):
                    names.append(name)
        return sorted(names)

    def preflight(self) -> dict[str, Any]:
        """Check the pinned model is loaded — without generating anything.

        Connectivity only, by design: the first real generation from a pinned arm
        closes design doc §6.3's pre-registration amendment window, so a
        preflight that "just tried one question" would spend a
        procedurally-significant event on a smoke test.
        """
        available = self.available_models()
        present = any(model_matches(self.pin.model, name) for name in available)
        return {
            "endpoint": self.pin.endpoint,
            "model": self.pin.model,
            "model_present": present,
            "available_models": available,
        }


# ---------------------------------------------------------------------------
# Answering and extraction prompts
# ---------------------------------------------------------------------------

# The rubrics are fixed strings rather than per-call constructions so that every
# arm and every question is asked in exactly the same words — the prompt is part
# of the shared pipeline, and a prompt that varied by arm would be a second
# independent variable (design doc §2, §7.3).

ANSWER_SYSTEM_PROMPT = (
    "You answer questions from a user's stored memory. Use ONLY the numbered "
    "memory items provided. If several items conflict, prefer the most recent "
    "one. If the items do not contain the answer, reply exactly: The "
    "information provided is not enough. Reply with the answer only - no "
    "explanation, no restatement of the question."
)

EXTRACT_SYSTEM_PROMPT = (
    "You extract atomic memory claims from one conversation session. Write one "
    "self-contained claim per line, in the order the facts appear. Each line "
    "must stand alone without the conversation: resolve pronouns, keep concrete "
    "values (numbers, dates, times, names) verbatim, and keep the speaker "
    "explicit. Do not number the lines, do not add bullets, do not add "
    "commentary. Output nothing except the claim lines."
)


def render_context(claims: Sequence[Claim]) -> str:
    """Render retrieved claims as the numbered memory block the rubric names."""
    return "\n".join(f"{index}. {claim.text}" for index, claim in enumerate(claims, 1))


def answer_messages(question: str, claims: Sequence[Claim]) -> list[dict[str, str]]:
    """The chat payload for one answering call.

    The retrieved claims are the *only* difference between arms — same model,
    same knobs, same rubric, same question — which is exactly the design's
    single-independent-variable constraint made concrete.
    """
    context = render_context(claims) or "(no memory items retrieved)"
    return [
        {"role": "system", "content": ANSWER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Memory items:\n{context}\n\nQuestion: {question}",
        },
    ]


def extract_messages(text: str) -> list[dict[str, str]]:
    """The chat payload for one extraction call."""
    return [
        {"role": "system", "content": EXTRACT_SYSTEM_PROMPT},
        {"role": "user", "content": f"Session:\n{text}"},
    ]


def extracted_lines(completion: str) -> list[str]:
    """Split an extraction completion into claim bodies.

    Blank lines are dropped and interior whitespace is collapsed, matching what
    :class:`~benchmarks.longmemeval.linker.SharedLinker` expects: it splits its
    input on newlines and mints one claim per non-blank line, so the shape of
    this list *is* the claim set every arm will see.
    """
    lines = []
    for raw in completion.split("\n"):
        body = " ".join(raw.split())
        if body:
            lines.append(body)
    return lines


# ---------------------------------------------------------------------------
# The judge CLI
# ---------------------------------------------------------------------------

# The two verdict tokens the judge rubric permits. Parsing accepts nothing else:
# design doc §6.1 makes turning a judgement into a boolean the *prompt's* job,
# and pipeline.build_judge refuses to coerce whatever comes back, so an
# unparseable verdict has to be an error rather than a default.
VERDICT_CORRECT = "CORRECT"
VERDICT_INCORRECT = "INCORRECT"

JUDGE_PROMPT_TEMPLATE = (
    "You are grading one answer against a reference answer.\n\n"
    "Question: {question}\n"
    "Reference answer: {gold}\n"
    "Candidate answer: {candidate}\n\n"
    "The candidate is CORRECT if it conveys the same information as the "
    "reference answer for this question, even if it is worded differently, "
    "more verbose, or more precise. It is INCORRECT if it states a different "
    "value, contradicts the reference, or fails to answer the question.\n"
    f"Reply with exactly one word on the final line: {VERDICT_CORRECT} or "
    f"{VERDICT_INCORRECT}."
)

# How long one judgement may take before it is abandoned and retried by hand.
DEFAULT_JUDGE_TIMEOUT_SECONDS = 300.0

# Where the prompt is handed to the CLI. ``stdin`` is the default because the
# candidate answer is model-generated text of unbounded length and unrestricted
# content: on this platform a command line is capped at ~32k characters, so a
# long answer passed as an argument would fail late, mid-run, on exactly the
# verbose answers most worth judging. ``argv`` is kept selectable because which
# form a given CLI build accepts is an operational fact about the installed tool,
# and the driver must be able to switch without a code change.
PROMPT_VIA_STDIN = "stdin"
PROMPT_VIA_ARGV = "argv"
PROMPT_VIA_CHOICES = (PROMPT_VIA_STDIN, PROMPT_VIA_ARGV)


@dataclass(frozen=True)
class ProcessResult:
    """One finished subprocess, with its streams still as raw bytes.

    Bytes, not ``str``, is the whole point. ``subprocess.run(text=True)`` decodes
    with the locale encoding inside its reader thread; on this platform that is
    not UTF-8, and a decode failure there surfaces as ``stdout=None`` with
    ``returncode=0`` and no exception — a judgement that silently disappears
    while the run reports success. Capturing bytes and decoding explicitly moves
    that failure into the open (2026-08-14 devlog).
    """

    returncode: int
    stdout: bytes
    stderr: bytes


# A runner takes (argv, stdin bytes or None, timeout) and returns a
# :class:`ProcessResult`. Injectable so tests drive the full command
# construction, decoding and verdict-parsing path without spawning anything.
Runner = Callable[[Sequence[str], bytes | None, float], ProcessResult]


def _subprocess_runner(
    argv: Sequence[str], stdin: bytes | None, timeout: float
) -> ProcessResult:
    """Run ``argv`` with no shell, capturing both streams as bytes.

    A hung or unlaunchable command is converted to :class:`JudgeTransportError`
    rather than surfacing as ``TimeoutExpired``/``OSError``. The distinction
    matters mid-run: the judging phase is a long loop over a subscription CLI,
    and its callers are written against the typed errors, so a foreign exception
    escaping here would read as a harness crash rather than as the retryable
    transport failure it is.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - argv comes from the pinned command
            list(argv),
            input=stdin,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise JudgeTransportError(
            f"the judge command did not finish within {timeout}s and was killed. "
            "Nothing is scored from a timed-out judgement; re-run to resume, or "
            "raise the timeout."
        ) from exc
    except OSError as exc:
        raise JudgeTransportError(f"the judge command could not be run: {exc}") from exc

    return ProcessResult(
        returncode=completed.returncode,
        stdout=completed.stdout or b"",
        stderr=completed.stderr or b"",
    )


class JudgeUnavailableError(RuntimeError):
    """The pinned judge command is not installed or not on PATH."""


class JudgeTransportError(RuntimeError):
    """The judge ran but produced nothing this harness may score.

    Distinct from :class:`~benchmarks.longmemeval.pipeline.JudgeVerdictError`,
    which means the judge *spoke* and was not understood. Both stop the row; only
    this one is worth retrying by hand.
    """


def decode_stream(raw: bytes, *, stream: str) -> str:
    """Decode one captured stream as strict UTF-8, or say precisely why not.

    Never ``errors="replace"``: a substitution inside a verdict or an error
    message is silent corruption of the very evidence being read.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JudgeTransportError(
            f"judge {stream} is not valid UTF-8 ({exc}); first bytes: "
            f"{raw[:80]!r}. It is not decoded with errors='replace' on purpose."
        ) from exc


def parse_verdict(output: str) -> bool:
    """Read the judge's final line as a strict ``CORRECT`` / ``INCORRECT`` token.

    The rubric asks for the verdict on the final line, so the final non-blank
    line is what is read, and it must be *exactly* one of the two tokens (case
    and a trailing period aside). Anything else raises
    :class:`~benchmarks.longmemeval.pipeline.JudgeVerdictError`.

    There is deliberately no "treat an unreadable verdict as incorrect" branch.
    That default is not neutral: judge failures are not independent of the arm
    being judged — a long, hedged answer is both likelier to derail the judge and
    likelier to come from one arm — so defaulting would push a systematic,
    arm-correlated error straight into M1's gate.
    """
    lines = [line.strip() for line in output.split("\n") if line.strip()]
    if not lines:
        raise JudgeVerdictError(
            "the judge returned no non-blank output, so there is no verdict to "
            "read. This is not scored as incorrect: an unreadable verdict is a "
            "missing measurement, not a wrong answer."
        )

    verdict_word = lines[-1].rstrip(".").strip().upper()
    if verdict_word == VERDICT_CORRECT:
        return True
    if verdict_word == VERDICT_INCORRECT:
        return False
    raise JudgeVerdictError(
        f"the judge's final line {lines[-1]!r} is neither {VERDICT_CORRECT!r} "
        f"nor {VERDICT_INCORRECT!r}. The pinned rubric (design doc §6.1) makes "
        "producing a parseable verdict the prompt's job; this harness will not "
        "infer one from prose."
    )


@dataclass
class JudgeClient:
    """The pinned judge model, reached by running its CLI once per judgement.

    The pre-registration also names a *fallback* judge. It is deliberately not
    wired as an automatic failover: swapping judges mid-batch would score part of
    one blind batch with a different model while the results carry a single judge
    pin, which is precisely the unattributable state
    :class:`~benchmarks.longmemeval.pipeline.UnrecordedPinsError` and the §6.1
    blind-scoring protocol exist to prevent. Falling back is an operator
    decision: re-run the judging phase with the fallback pin, and the results
    then record that model. :attr:`fallback_model` is carried so the run manifest
    can state which model that would be.
    """

    cli_pin: CliPin
    timeout_seconds: float = DEFAULT_JUDGE_TIMEOUT_SECONDS
    prompt_via: str = PROMPT_VIA_STDIN
    runner: Runner = _subprocess_runner
    resolver: Callable[[str], str | None] = shutil.which
    _executable: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.prompt_via not in PROMPT_VIA_CHOICES:
            raise ValueError(
                f"prompt_via must be one of {PROMPT_VIA_CHOICES}, got "
                f"{self.prompt_via!r}"
            )

    @property
    def pin(self) -> ModelPin:
        """The recorded identity of the model this client reaches."""
        return self.cli_pin.pin

    @property
    def fallback_model(self) -> str | None:
        return self.cli_pin.fallback_model

    def executable(self) -> str:
        """The resolved path of the pinned command.

        Resolved through :func:`shutil.which` rather than handed to the OS as a
        bare name: on this platform a bare name is looked up as an ``.exe`` only,
        so a CLI installed as a shim script would simply not be found. Resolving
        once also means a mid-run PATH change cannot silently move which binary a
        run is judging with.
        """
        if self._executable is None:
            resolved = self.resolver(self.cli_pin.argv[0])
            if resolved is None:
                raise JudgeUnavailableError(
                    f"the pinned judge command {self.cli_pin.argv[0]!r} was not "
                    "found on PATH, so the judge stage cannot run. The command is "
                    "read from benchmarks/longmemeval/preregister.json "
                    "(design doc §5.2)."
                )
            self._executable = resolved
        return self._executable

    def _argv(self, prompt: str) -> list[str]:
        argv = [self.executable(), *self.cli_pin.argv[1:], "--model", self.pin.model]
        if self.prompt_via == PROMPT_VIA_ARGV:
            argv.append(prompt)
        return argv

    def _run(self, argv: Sequence[str], stdin: bytes | None) -> str:
        result = self.runner(argv, stdin, self.timeout_seconds)
        if result.returncode != 0:
            raise JudgeTransportError(
                f"the judge command exited {result.returncode}: "
                f"{decode_stream(result.stderr, stream='stderr').strip()!r}"
            )
        if not result.stdout:
            raise JudgeTransportError(
                "the judge command exited 0 but wrote nothing to stdout. On this "
                "platform that is the signature of a decode failure inside the "
                "subprocess reader thread — which is why this client captures "
                "bytes and decodes them itself. Nothing is scored from an empty "
                "transcript."
            )
        return decode_stream(result.stdout, stream="stdout")

    def verdict(self, question: str, gold: str, candidate_answer: str) -> bool:
        """Judge one candidate answer. No arm label is passed, ever.

        The payload is exactly ``(question, gold, candidate_answer)``, which is
        the whole of design doc §6.1 guard 1's judge contract: the arm is carried
        only by the harness-side slot bookkeeping in
        :func:`~benchmarks.longmemeval.pipeline.score_blind`.
        """
        prompt = JUDGE_PROMPT_TEMPLATE.format(
            question=question, gold=gold, candidate=candidate_answer
        )
        argv = self._argv(prompt)
        stdin = prompt.encode("utf-8") if self.prompt_via == PROMPT_VIA_STDIN else None
        return parse_verdict(self._run(argv, stdin))

    def preflight(self) -> dict[str, Any]:
        """Check the judge CLI runs at all — without judging anything.

        ``--version`` and nothing else: the first judgement of a real arm is part
        of the pinned run, not a connectivity probe.
        """
        argv = [self.executable(), "--version"]
        result = self.runner(argv, None, self.timeout_seconds)
        return {
            "command": self.cli_pin.argv[0],
            "executable": self.executable(),
            "model": self.pin.model,
            "fallback_model": self.fallback_model,
            "returncode": result.returncode,
            "version": decode_stream(result.stdout, stream="stdout").strip(),
            "runs": result.returncode == 0,
        }

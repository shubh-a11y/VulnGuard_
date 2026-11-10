"""Reusable, vulnerability-class exploit strategies.

This is deliberately *not* a mapping from function names to payloads. A
strategy is selected from the diagnosed vulnerability type / CWE and describes
generic, reusable properties of a proof of concept:

* what has to be set up (a database schema, a file, a template directory),
* how the malicious input reaches the defect,
* which observable effect proves it during sandbox execution.

Language mechanics (how to compile, how to import the module, how to print a
marker) stay in the adapters. A new repository therefore needs no new strategy:
the same SQL-injection strategy applies to any function in any Python/SQL code
base.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExploitStrategy:
    """Language-independent guidance for one vulnerability class."""

    key: str
    cwe_ids: tuple[str, ...]
    type_keywords: tuple[str, ...]
    prerequisites: str
    observable: str
    guidance: str

    def prompt_block(self) -> str:
        return (
            f"Class: {self.key}\n"
            f"Typical prerequisites: {self.prerequisites}\n"
            f"Observable proof: {self.observable}\n"
            f"Approach: {self.guidance}"
        )


# Ordered by specificity: the first matching CWE/type wins.
_STRATEGIES: tuple[ExploitStrategy, ...] = (
    ExploitStrategy(
        key="SQL_INJECTION",
        cwe_ids=("CWE-89", "CWE-564"),
        type_keywords=("SQL", "QUERY", "DATABASE"),
        prerequisites=(
            "a database the target actually opens; create an in-memory SQLite "
            "database with the table and columns the query references and, when "
            "the target opens its own connection, point it at a temporary file "
            "or monkeypatch the connector inside the harness"
        ),
        observable=(
            "a row the query should not return (e.g. all rows via a tautology or "
            "comment truncation), a SQL error, or a payload that changes the "
            "result set without the quoted input being treated as data"
        ),
        guidance=(
            "Derive the schema from the real query/ORM call in the target, seed "
            "one benign row plus one row that only an injected predicate can "
            "return, then assert on the returned data rather than on an exception."
        ),
    ),
    ExploitStrategy(
        key="COMMAND_INJECTION",
        cwe_ids=("CWE-78", "CWE-77", "CWE-88"),
        type_keywords=("COMMAND", "SHELL", "OS_INJECTION", "EXEC"),
        prerequisites=(
            "a benign, isolated side effect the injected command can create, "
            "such as a file under /tmp; never a destructive or network command"
        ),
        observable=(
            "the side-effect file exists (or its content is readable) after the "
            "target runs, proving the injected command executed"
        ),
        guidance=(
            "Append a separator plus a harmless `touch`/`echo` to the argument the "
            "target interpolates into the shell, run the target, then check the "
            "side effect. Do not print the marker for any exception."
        ),
    ),
    ExploitStrategy(
        key="BUFFER_OVERFLOW",
        cwe_ids=("CWE-120", "CWE-121", "CWE-122", "CWE-787", "CWE-788"),
        type_keywords=("BUFFER", "OVERFLOW", "OUT_OF_BOUNDS", "MEMORY"),
        prerequisites=(
            "a payload longer than the destination buffer; the sandbox compiles "
            "the target with AddressSanitizer and stack protector enabled"
        ),
        observable=(
            "a sanitizer report, 'stack smashing detected', or a segmentation "
            "fault produced by the overflowing input"
        ),
        guidance=(
            "Call the real target with a boundary-crossing string (for example a "
            "pattern of 'A' bytes longer than the smallest buffer in the function). "
            "The harness must let the crash happen; it must not catch signals or "
            "print the marker unconditionally."
        ),
    ),
    ExploitStrategy(
        key="FORMAT_STRING",
        cwe_ids=("CWE-134",),
        type_keywords=("FORMAT", "PRINTF"),
        prerequisites="a format string containing %n/%s specifiers as attacker input",
        observable=(
            "the target reads or writes memory it should not (crash, sanitizer "
            "report, or a value derived from the stack)"
        ),
        guidance=(
            "Pass a format string such as '%s%s%s%s' or '%n' through the real "
            "non-literal format sink. A crash from the format engine is the proof; "
            "an ordinary printf of the payload is not."
        ),
    ),
    ExploitStrategy(
        key="PATH_TRAVERSAL",
        cwe_ids=("CWE-22", "CWE-23", "CWE-36"),
        type_keywords=("PATH", "TRAVERSAL", "DIRECTORY", "FILE_READ"),
        prerequisites=(
            "an isolated temporary directory with a sentinel file outside the "
            "intended root; create both inline with the standard library"
        ),
        observable=(
            "the target returns or writes the sentinel content from outside the "
            "allowed directory"
        ),
        guidance=(
            "Create /tmp/<unique>/allowed and /tmp/<unique>/secret.txt, then pass "
            "'../secret.txt' (and an absolute variant) to the real target and "
            "assert the sentinel content appears."
        ),
    ),
    ExploitStrategy(
        key="TOCTOU",
        cwe_ids=("CWE-367", "CWE-362", "CWE-363"),
        type_keywords=("TOCTOU", "RACE", "SYMLINK"),
        prerequisites=(
            "two filesystem paths and, where needed, a helper thread/process that "
            "swaps them between the check and the use"
        ),
        observable=(
            "the operation succeeds on a path that was replaced after the check "
            "(for example the target follows a symlink created in the race window)"
        ),
        guidance=(
            "Describe the interleaving concretely and keep it bounded: create the "
            "safe file, start a short-lived thread that swaps it for a symlink to "
            "the sentinel, invoke the target, and assert on the resulting file "
            "content. A flaky race may be repeated a bounded number of times."
        ),
    ),
    ExploitStrategy(
        key="XSS",
        cwe_ids=("CWE-79", "CWE-80"),
        type_keywords=("XSS", "CROSS_SITE", "HTML_INJECTION"),
        prerequisites=(
            "an application-level rendering path or template environment the "
            "target uses; use the framework's own test client when available"
        ),
        observable=(
            "unescaped markup from the input appears in the rendered output, or a "
            "browser-equivalent parser treats it as executable markup"
        ),
        guidance=(
            "Call the real renderer/response builder with a payload containing a "
            "unique element id inside a tag, then assert the raw tag is present in "
            "the output instead of being escaped."
        ),
    ),
    ExploitStrategy(
        key="CODE_INJECTION",
        cwe_ids=("CWE-94", "CWE-95", "CWE-1336"),
        type_keywords=("CODE_INJECTION", "EVAL", "EXEC", "TEMPLATE_INJECTION"),
        prerequisites="no external service; use a benign expression with a unique side effect",
        observable=(
            "the injected expression is evaluated (a computed value or a created "
            "file proves the code path ran)"
        ),
        guidance=(
            "Pass the smallest expression the target will evaluate, such as a call "
            "that writes a marker file, and check the side effect rather than "
            "matching a traceback."
        ),
    ),
    ExploitStrategy(
        key="DESERIALIZATION",
        cwe_ids=("CWE-502",),
        type_keywords=("DESERIAL", "PICKLE", "YAML", "MARSHAL"),
        prerequisites="a serialized blob the target deserializes; build it inline",
        observable=(
            "a side effect from the deserialized object (created file or computed "
            "value) demonstrates arbitrary object construction"
        ),
        guidance=(
            "Serialise a benign object whose reconstruction writes a marker file, "
            "feed it to the real deserialization call, and assert on the file."
        ),
    ),
    ExploitStrategy(
        key="SSRF",
        cwe_ids=("CWE-918",),
        type_keywords=("SSRF", "SERVER_SIDE_REQUEST", "URL_FETCH"),
        prerequisites=(
            "a loopback HTTP listener started inside the harness that records one "
            "request; the sandbox has no external network"
        ),
        observable="the local listener received the request the target constructed",
        guidance=(
            "Start a one-request local server, pass its URL as the attacker input, "
            "invoke the target, and assert the request arrived."
        ),
    ),
    ExploitStrategy(
        key="XXE",
        cwe_ids=("CWE-611", "CWE-776"),
        type_keywords=("XXE", "XML_EXTERNAL", "ENTITY"),
        prerequisites="an XML document with an external entity pointing at a local sentinel file",
        observable="the sentinel file content appears in the parsed output",
        guidance=(
            "Build the document inline, parse it with the real sink, and assert the "
            "sentinel appears."
        ),
    ),
    ExploitStrategy(
        key="OPEN_REDIRECT",
        cwe_ids=("CWE-601",),
        type_keywords=("REDIRECT",),
        prerequisites="no external service; inspect the redirect target the code returns",
        observable="the returned Location/redirect value points at the attacker host",
        guidance=(
            "Call the real handler with an absolute external URL and assert the "
            "returned redirect target is that host."
        ),
    ),
    ExploitStrategy(
        key="LDAP_INJECTION",
        cwe_ids=("CWE-90",),
        type_keywords=("LDAP",),
        prerequisites="a local LDAP filter parser or stub the target calls",
        observable="the filter matches more entries than the intended exact match",
        guidance=(
            "Stub the smallest directory interface the target uses, then assert the "
            "injected filter returns the extra entry."
        ),
    ),
)


_GENERIC = ExploitStrategy(
    key="GENERIC_DEFECT",
    cwe_ids=(),
    type_keywords=(),
    prerequisites=(
        "only what the target itself needs; set it up inline with the standard "
        "library and never rely on the network or a missing file"
    ),
    observable=(
        "a concrete, attacker-caused effect the secure version cannot produce "
        "(wrong data returned, a file created, a crash, an elevated permission)"
    ),
    guidance=(
        "Reach the exact sink described in the diagnosis with the smallest input "
        "that changes behaviour, and assert on that change instead of on an "
        "exception or on the marker being printed unconditionally."
    ),
)


def _normalise(value: str) -> str:
    return "".join(ch for ch in value.upper() if ch.isalnum() or ch == "_")


def strategy_for(
    vulnerability_type: str | None,
    cwe_id: str | None = None,
) -> ExploitStrategy:
    """Pick a reusable strategy from the diagnosis, never from a function name."""
    cwe = (cwe_id or "").upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
    for strategy in _STRATEGIES:
        if cwe and cwe in strategy.cwe_ids:
            return strategy

    haystack = _normalise(f"{vulnerability_type or ''}")
    best: ExploitStrategy | None = None
    best_hits = 0
    for strategy in _STRATEGIES:
        hits = sum(1 for keyword in strategy.type_keywords if keyword in haystack)
        if hits > best_hits:
            best, best_hits = strategy, hits
    return best or _GENERIC


def strategy_keys() -> tuple[str, ...]:
    """The documented strategy set (used by the docs and the adapter tests)."""
    return tuple(strategy.key for strategy in _STRATEGIES) + (_GENERIC.key,)


def strategy_catalog() -> str:
    """Compact catalogue for a request that must choose its own class.

    The single structured Red Agent request produces the diagnosis, so the
    vulnerability class is not known before the call. Sending every class's
    observable proof and approach (a few lines each) is still small, and the
    model applies the one matching its own diagnosis. Once a diagnosis exists
    (regeneration), `strategy_for` narrows it to a single block.
    """
    blocks = []
    for strategy in _STRATEGIES:
        blocks.append(
            f"- {strategy.key}: setup = {strategy.prerequisites}; "
            f"proof = {strategy.observable}; approach = {strategy.guidance}"
        )
    blocks.append(
        f"- {_GENERIC.key} (use when nothing matches): setup = {_GENERIC.prerequisites}; "
        f"proof = {_GENERIC.observable}; approach = {_GENERIC.guidance}"
    )
    return "\n".join(blocks)

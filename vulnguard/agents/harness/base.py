"""Language-specific exploit harness adapters.

The Red Agent owns vulnerability reasoning: what the defect is, which input
reaches it, and what observable effect proves it. Everything that depends on
the *target language's* execution mechanics lives behind a ``HarnessAdapter``:

* which source markers identify the language (and which betray a different one),
* the minimal program shape the model should adapt,
* how to import/link the target from the uploaded workspace,
* what must be true before the harness may be executed,
* the command the sandbox uses to run it,
* what infrastructure the harness may legitimately assume.

Adapters are deliberately small and declarative. Adding a language does not
duplicate the Red Agent; it adds one adapter and one sandbox command.
"""

from __future__ import annotations

from typing import Any, Mapping


class HarnessAdapter:
    """Base adapter. Subclasses override the capabilities their language has.

    ``runtime_status`` documents what is actually implemented, and is surfaced
    in the prompt so the model never assumes a runtime that is not there:

    * ``verified``      — generated, statically validated and executed by the
                          sandbox runner.
    * ``experimental``  — generation/validation/execution are wired, but the
                          runtime inside the sandbox image is not guaranteed.
    * ``unsupported``   — no execution path exists yet; a harness may still be
                          produced for a human to run, but it is never reported
                          as validated.
    """

    language: str = "generic"
    display_name: str = "Generic"
    aliases: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    foreign_markers: tuple[str, ...] = ()
    runtime_status: str = "unsupported"
    runtime_note: str = ""
    requires_entry_point: bool = False

    # ── Prompt material ──────────────────────────────────────────────

    def shape(self) -> str:
        """A minimal, language-correct skeleton the model can adapt."""
        return (
            f"Write a complete runnable {self.language} program with an entry "
            "point, load or link the supplied workspace target, and print "
            "VULNGUARD_POC_SUCCESS only after the defect is proven."
        )

    def workspace_target_instruction(self, state: Mapping[str, Any]) -> str:
        """Concrete instruction for invoking *this* target from a harness."""
        return (
            "Compile or load the harness together with the supplied workspace "
            "source, then invoke the target with its real signature."
        )

    def prerequisite_notes(self, vulnerability_type: str) -> tuple[str, ...]:
        """Language-level constraints a harness must respect (no function names)."""
        return ()

    def capability_note(self) -> str:
        note = f"Sandbox runtime status for {self.display_name}: {self.runtime_status}."
        if self.runtime_note:
            note += f" {self.runtime_note}"
        return note

    # ── Validation ───────────────────────────────────────────────────

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        """Return why this harness may not be executed, or ``None``.

        Only language mechanics belong here. Generic checks (prose/refusal,
        missing success signal, dangerous payloads) live in the Red Agent so
        they cannot be forgotten by a new adapter.
        """
        return None

    def execution_command(self, exploit_path: str) -> str:
        """The command the sandbox uses; mirrors ``DockerRunner.run_exploit``."""
        return f"sh {exploit_path}"

    # ── Introspection ────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "runtime_status": self.runtime_status,
            "requires_entry_point": self.requires_entry_point,
        }


def target_symbol(state: Mapping[str, Any]) -> str:
    """The function/method name under analysis.

    Pipeline state carries ``function_id``; upload payloads use ``id``/``name``.
    Accepting both keeps the adapters usable from the dashboard, the CLI and
    the evaluation harness without a conversion layer.
    """
    function_id = str(state.get("function_id") or state.get("id") or "")
    if function_id:
        return function_id.rsplit(":", 1)[-1]
    return str(state.get("name") or "")

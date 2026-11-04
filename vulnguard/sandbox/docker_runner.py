"""
Docker sandbox runner — resource-constrained container execution.

Runs build, test, and exploit commands in isolated Docker containers
with strict security limits (Section 4.3). Handles Windows path
translation (EC-8.4), Docker health checks (EC-8.1), and unique
container naming (Section 4.6).
"""

from __future__ import annotations

import logging
import os
import platform
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional
from uuid import uuid4

from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class DockerNotAvailableError(RuntimeError):
    """Raised when the Docker sandbox is not ready."""

    def __init__(self, message: str = ""):
        super().__init__(
            message
            or "Docker is not available. Ensure Docker Desktop is running.\n"
            "Install: https://docs.docker.com/get-docker/\n"
            "On Windows, Docker Desktop or WSL2 with Docker is required."
        )


# ── Result dataclasses ────────────────────────────────────────────────────

@dataclass
class CommandResult:
    """Result of a sandbox command execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str

    @property
    def combined_output(self) -> str:
        out = ""
        if self.stdout:
            out += self.stdout
        if self.stderr:
            out += "\n--- STDERR ---\n" + self.stderr
        return out


# ── Path translation (EC-8.4) ────────────────────────────────────────────

def _to_docker_mount_path(host_path: str) -> str:
    """Convert Windows paths to Docker-compatible mount paths.

    Docker Desktop on Windows expects paths like /c/Users/... for bind mounts
    when using certain backends.
    """
    if platform.system() != "Windows":
        return host_path

    p = Path(host_path).resolve()
    # C:\Users\foo → /c/Users/foo
    drive = p.drive.rstrip(":")
    posix = PurePosixPath("/", drive.lower(), *p.parts[1:])
    return str(posix)


def _workspace_relative_path(file_path: str, repo_root: str) -> str:
    """Return a safe POSIX path for a file contained by the repository."""
    try:
        relative = Path(file_path).resolve().relative_to(Path(repo_root).resolve())
    except ValueError as exc:
        raise ValueError("Target file must be inside the repository root") from exc
    return relative.as_posix()


# ── Docker client singleton ──────────────────────────────────────────────

_docker_client = None
_last_docker_error = ""


def _docker_error_message(exc: Exception) -> str:
    detail = str(exc).strip() or exc.__class__.__name__
    if "Access is denied" in detail or "CreateFile" in detail and "(5," in detail:
        return (
            "Docker Desktop is running, but this process cannot access its Windows named pipe. "
            "Restart Docker Desktop and this terminal under the same Windows user, then run "
            "`python -m vulnguard.main doctor --build-sandbox`. "
            f"Docker error: {detail}"
        )
    return f"Docker engine is not ready: {detail}"


def ensure_sandbox_ready(build_if_missing: bool = False):
    """Connect to Docker and optionally build the configured sandbox image."""
    global _docker_client, _last_docker_error
    try:
        import docker

        client = docker.from_env()
        client.ping()
        try:
            client.images.get(cfg.sandbox.sandbox_image)
        except docker.errors.ImageNotFound as exc:
            if not build_if_missing:
                raise DockerNotAvailableError(
                    f"Docker image '{cfg.sandbox.sandbox_image}' is missing. Run:\n"
                    "python -m vulnguard.main doctor --build-sandbox"
                ) from exc
            sandbox_dir = Path(__file__).resolve().parent
            client.images.build(
                path=str(sandbox_dir),
                dockerfile="Dockerfile",
                tag=cfg.sandbox.sandbox_image,
                rm=True,
            )
        _docker_client = client
        _last_docker_error = ""
        return client
    except DockerNotAvailableError as exc:
        _last_docker_error = str(exc)
        raise
    except Exception as exc:
        _last_docker_error = _docker_error_message(exc)
        logger.error("Docker health check failed: %s", exc)
        raise DockerNotAvailableError(_last_docker_error) from exc


def _get_client():
    """Get or create Docker client with health check (EC-8.1)."""
    global _docker_client
    if _docker_client is not None:
        try:
            _docker_client.ping()
            return _docker_client
        except Exception:
            _docker_client = None

    return ensure_sandbox_ready()


# ── Container execution ──────────────────────────────────────────────────

class DockerRunner:
    """Manages sandboxed container execution with security constraints."""

    def __init__(self):
        self._client = _get_client()

    def _run_container(
        self,
        command: str,
        repo_root: str = "",
        extra_files: dict[str, str] | None = None,
        env_vars: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run a command in an isolated Docker container.

        Args:
            command: Shell command to execute inside the container.
            repo_root: Host path to mount as /workspace (read-only).
            extra_files: Dict of {container_path: content} to write before execution.
            env_vars: Environment variables to inject.
            timeout: Execution timeout in seconds.

        Returns:
            CommandResult with exit code and output.
        """
        timeout = timeout or cfg.sandbox.execution_timeout_seconds
        container_name = f"vulnguard_sandbox_{uuid4().hex[:8]}"
        archive_files = dict(extra_files or {})
        seed_copies: list[str] = []
        input_dir = tempfile.TemporaryDirectory(prefix="vulnguard_inputs_")
        input_root = Path(input_dir.name)

        for index, (target_path, content) in enumerate(archive_files.items()):
            seed_name = f"{index}_{PurePosixPath(target_path).name}"
            (input_root / seed_name).write_text(content, encoding="utf-8")
            seed_path = f"/vulnguard_inputs/{seed_name}"
            seed_copies.append(
                f"mkdir -p {shlex.quote(str(PurePosixPath(target_path).parent))} && "
                f"cp -- {shlex.quote(seed_path)} {shlex.quote(target_path)}"
            )
        (input_root / "vulnguard_run.sh").write_text(
            f"set -eu\n{command}\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chmod(input_root, 0o755)

        workspace_setup = "mkdir -p /tmp/workspace"
        if repo_root and os.path.isdir(repo_root):
            workspace_setup += " && cp -R /host_workspace/. /tmp/workspace/"
        setup_command = " && ".join([workspace_setup, *seed_copies])

        # Build container config (Section 4.3 security constraints)
        run_kwargs: dict = {
            "image": cfg.sandbox.sandbox_image,
            "command": [
                "sh",
                "-c",
                f"{setup_command} && cd /tmp/workspace && "
                "sh /vulnguard_inputs/vulnguard_run.sh",
            ],
            "name": container_name,
            "mem_limit": cfg.sandbox.memory_limit,
            "cpu_count": cfg.sandbox.cpu_count,
            "pids_limit": cfg.sandbox.pids_limit,
            "network_mode": cfg.sandbox.network_mode,
            "read_only": True,
            "tmpfs": {"/tmp": "size=100m,exec,uid=65534,gid=65534,mode=1777"},
            "user": "65534:65534",
            "volumes": {
                _to_docker_mount_path(input_dir.name): {
                    "bind": "/vulnguard_inputs",
                    "mode": "ro",
                },
            },
            "auto_remove": False,  # We need to fetch logs before removal
            "cap_drop": ["ALL"],
        }

        # Mount repo if provided
        if repo_root and os.path.isdir(repo_root):
            mount_path = _to_docker_mount_path(repo_root)
            run_kwargs["volumes"][mount_path] = {"bind": "/host_workspace", "mode": "ro"}

        # Environment variables (EC-8.2)
        env = {"HOME": "/tmp"}
        if cfg.sandbox.env_file and os.path.isfile(cfg.sandbox.env_file):
            with open(cfg.sandbox.env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        env[k.strip()] = v.strip()
        if env_vars:
            env.update(env_vars)
        if env:
            run_kwargs["environment"] = env

        container = None
        try:
            container = self._client.containers.create(**run_kwargs)
            container.start()

            # Wait for completion
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            return CommandResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                stdout=stdout[-5000:],  # Cap output
                stderr=stderr[-5000:],
            )

        except Exception as exc:
            logger.error("Container execution failed: %s", exc)
            return CommandResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            input_dir.cleanup()

    def run_build(
        self,
        repo_root: str,
        file_path: str = "",
        code: str = "",
        build_command: str = "",
    ) -> CommandResult:
        """Run a build/compilation check.

        If build_command is not provided, auto-detects based on repo contents.
        """
        # Auto-detect build system
        if not build_command:
            build_command = self._detect_build_command(repo_root)

        extra = {}
        if file_path and code:
            container_file = f"/tmp/patched_{Path(file_path).name}"
            extra[container_file] = code
            rel_path = _workspace_relative_path(file_path, repo_root)
            destination = f"/tmp/workspace/{rel_path}"
            build_command = (
                f"cp -- {shlex.quote(container_file)} {shlex.quote(destination)} && {build_command}"
            )

        return self._run_container(
            command=build_command,
            repo_root=repo_root,
            extra_files=extra if extra else None,
        )

    def run_tests(
        self,
        repo_root: str,
        test_command: str = "",
        file_path: str = "",
        code: str = "",
    ) -> CommandResult:
        """Run the project's test suite."""
        if not test_command:
            test_command = self._detect_test_command(repo_root)

        extra = {}
        if file_path and code:
            container_file = f"/tmp/patched_{Path(file_path).name}"
            extra[container_file] = code
            rel_path = _workspace_relative_path(file_path, repo_root)
            destination = f"/tmp/workspace/{rel_path}"
            test_command = (
                f"cp -- {shlex.quote(container_file)} {shlex.quote(destination)} && {test_command}"
            )

        return self._run_container(
            command=test_command,
            repo_root=repo_root,
            extra_files=extra if extra else None,
        )

    def run_exploit(
        self,
        repo_root: str,
        exploit_code: str,
        target_code: str = "",
        file_path: str = "",
        language: str = "c",
    ) -> CommandResult:
        """Run a Red Agent PoC exploit in the sandbox.

        The exploit is written to /tmp and executed. Target code can be
        optionally patched before running.
        """
        ext_map = {"c": "c", "cpp": "cpp", "python": "py", "java": "java", "javascript": "js"}
        ext = ext_map.get(language, "txt")
        exploit_name = "Exploit.java" if language == "java" else f"vulnguard_exploit.{ext}"
        exploit_file = f"/tmp/workspace/{exploit_name}"

        # Build execution command
        run_cmd_map = {
            "c": f"gcc {exploit_file} -o /tmp/exploit_bin && echo VULNGUARD_EXECUTION_STARTED && /tmp/exploit_bin",
            "cpp": f"g++ {exploit_file} -o /tmp/exploit_bin && echo VULNGUARD_EXECUTION_STARTED && /tmp/exploit_bin",
            "python": f"echo VULNGUARD_EXECUTION_STARTED && python3 {exploit_file}",
            "java": f"javac {exploit_file} && echo VULNGUARD_EXECUTION_STARTED && java -cp /tmp/workspace Exploit",
            "javascript": f"echo VULNGUARD_EXECUTION_STARTED && node {exploit_file}",
        }
        run_cmd = run_cmd_map.get(language, f"sh {exploit_file}")

        extra = {exploit_file: exploit_code}
        if target_code and file_path:
            container_file = f"/tmp/{Path(file_path).name}"
            extra[container_file] = target_code
            rel_path = (
                _workspace_relative_path(file_path, repo_root)
                if repo_root
                else Path(file_path).name
            )
            destination = f"/tmp/workspace/{rel_path}"
            copy_target = f"cp -- {shlex.quote(container_file)} {shlex.quote(destination)}"
            if language in {"c", "cpp"}:
                compiler = "g++" if language == "cpp" else "gcc"
                safety_flags = "-fsanitize=address -fno-omit-frame-pointer -fstack-protector-all"
                run_cmd = (
                    f"{copy_target} && "
                    f"{compiler} {safety_flags} -Dmain=vulnguard_target_main "
                    f"-c {shlex.quote(destination)} "
                    f"-o /tmp/vulnguard_target.o && "
                    f"{compiler} {safety_flags} {shlex.quote(exploit_file)} "
                    f"/tmp/vulnguard_target.o "
                    "-o /tmp/exploit_bin && echo VULNGUARD_EXECUTION_STARTED && /tmp/exploit_bin"
                )
            else:
                run_cmd = f"{copy_target} && {run_cmd}"

        return self._run_container(
            command=run_cmd,
            repo_root=repo_root,
            extra_files=extra,
        )

    @staticmethod
    def _detect_build_command(repo_root: str) -> str:
        """Auto-detect build command from repo files."""
        root = Path(repo_root)
        if (root / "Makefile").exists():
            return "make -j$(nproc)"
        if (root / "CMakeLists.txt").exists():
            return "mkdir -p /tmp/build && cd /tmp/build && cmake /tmp/workspace && make -j$(nproc)"
        if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
            return "python3 -m pip install -e /tmp/workspace 2>&1"
        if (root / "package.json").exists():
            return "cd /tmp/workspace && npm ci && npm run build 2>&1"
        if (root / "pom.xml").exists():
            return "cd /tmp/workspace && mvn compile 2>&1"
        return "echo 'No build system detected — skipping build'"

    @staticmethod
    def _detect_test_command(repo_root: str) -> str:
        """Auto-detect test command from repo files."""
        root = Path(repo_root)
        if (root / "Makefile").exists():
            return "make test 2>&1"
        if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
            return "cd /tmp/workspace && python3 -m pytest -x 2>&1"
        if (root / "package.json").exists():
            return "cd /tmp/workspace && npm test 2>&1"
        if (root / "pom.xml").exists():
            return "cd /tmp/workspace && mvn test 2>&1"
        # Fallback to pytest for Python MVP
        return "cd /tmp/workspace && python3 -m pytest -x 2>&1"


def check_docker_available() -> bool:
    """Check Docker on every call so starting Desktop does not require a backend restart."""
    try:
        _get_client()
        return True
    except DockerNotAvailableError:
        return False


def get_docker_error() -> str:
    """Return the most recent actionable Docker diagnostic."""
    return _last_docker_error

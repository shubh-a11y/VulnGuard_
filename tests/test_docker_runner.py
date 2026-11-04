"""
Tests for the Docker runner module.

Tests path translation, health checks, and configuration — without
requiring Docker to be installed.
"""

import platform
import pytest
import docker
from unittest.mock import patch, MagicMock

from vulnguard.sandbox.docker_runner import (
    _to_docker_mount_path,
    _workspace_relative_path,
    DockerNotAvailableError,
    CommandResult,
    DockerRunner,
    check_docker_available,
    ensure_sandbox_ready,
)


class TestPathTranslation:
    """Test EC-8.4: Windows path translation."""

    @patch("vulnguard.sandbox.docker_runner.platform")
    def test_windows_path_conversion(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        result = _to_docker_mount_path(r"C:\Users\test\repo")
        assert result.startswith("/c/")
        assert "Users" in result
        assert "\\" not in result

    @patch("vulnguard.sandbox.docker_runner.platform")
    def test_linux_path_unchanged(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        path = "/home/user/repo"
        assert _to_docker_mount_path(path) == path


class TestDockerNotAvailable:
    """Test EC-8.1: Graceful Docker unavailability."""

    def test_error_message(self):
        err = DockerNotAvailableError()
        assert "Docker is not available" in str(err)
        assert "docs.docker.com" in str(err)

    def test_missing_image_has_build_instructions(self):
        import vulnguard.sandbox.docker_runner as docker_runner

        client = MagicMock()
        client.images.get.side_effect = docker.errors.ImageNotFound("missing")
        docker_runner._docker_client = None

        try:
            with patch("docker.from_env", return_value=client):
                with pytest.raises(DockerNotAvailableError, match="doctor --build-sandbox"):
                    docker_runner._get_client()
        finally:
            docker_runner._docker_client = None

    def test_availability_recovers_without_backend_restart(self):
        with patch(
            "vulnguard.sandbox.docker_runner._get_client",
            side_effect=[DockerNotAvailableError("not ready"), MagicMock()],
        ):
            assert check_docker_available() is False
            assert check_docker_available() is True

    def test_doctor_can_build_missing_sandbox_image(self):
        import vulnguard.sandbox.docker_runner as docker_runner

        client = MagicMock()
        client.images.get.side_effect = docker.errors.ImageNotFound("missing")
        docker_runner._docker_client = None

        try:
            with patch("docker.from_env", return_value=client):
                assert ensure_sandbox_ready(build_if_missing=True) is client
        finally:
            docker_runner._docker_client = None

        client.images.build.assert_called_once()


class TestCommandResult:
    def test_success_result(self):
        result = CommandResult(success=True, exit_code=0, stdout="OK", stderr="")
        assert result.success
        assert "OK" in result.combined_output

    def test_failure_result(self):
        result = CommandResult(success=False, exit_code=1, stdout="", stderr="error: build failed")
        assert not result.success
        assert "error" in result.combined_output

    def test_combined_output_includes_stderr(self):
        result = CommandResult(success=False, exit_code=1, stdout="line1", stderr="err1")
        combined = result.combined_output
        assert "line1" in combined
        assert "err1" in combined


class TestBuildCommandDetection:
    """Test auto-detection of build systems."""

    def test_makefile_detected(self, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n\tgcc -o main main.c")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "make" in cmd

    def test_cmake_detected(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "cmake" in cmd

    def test_python_project_detected(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "pip" in cmd

    def test_node_project_detected(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}')
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "npm" in cmd

    def test_no_build_system(self, tmp_path):
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "No build system" in cmd


class TestSandboxCommands:
    def test_test_failures_are_not_masked(self, tmp_path):
        command = DockerRunner._detect_test_command(str(tmp_path))
        assert "|| true" not in command
        assert "python3 -m pytest" in command

    def test_workspace_path_is_relative(self, tmp_path):
        target = tmp_path / "src" / "app.py"
        target.parent.mkdir()
        target.write_text("pass")
        assert _workspace_relative_path(str(target), str(tmp_path)) == "src/app.py"

    def test_workspace_path_rejects_external_file(self, tmp_path):
        with pytest.raises(ValueError, match="inside the repository"):
            _workspace_relative_path(str(tmp_path.parent / "outside.py"), str(tmp_path))

    def test_python_exploit_runs_from_workspace(self, tmp_path):
        target = tmp_path / "target.py"
        target.write_text("def target(): pass")
        runner = DockerRunner.__new__(DockerRunner)
        runner._run_container = MagicMock(return_value=CommandResult(True, 0, "", ""))

        runner.run_exploit(
            repo_root="",
            exploit_code="from target import target",
            target_code=target.read_text(),
            file_path=str(target),
            language="python",
        )

        kwargs = runner._run_container.call_args.kwargs
        assert "python3 /tmp/workspace/vulnguard_exploit.py" in kwargs["command"]
        assert "/tmp/workspace/target.py" in kwargs["command"]

    def test_c_exploit_links_workspace_target(self):
        runner = DockerRunner.__new__(DockerRunner)
        runner._run_container = MagicMock(return_value=CommandResult(True, 0, "", ""))

        runner.run_exploit(
            repo_root="",
            exploit_code="int main(void) { return target(); }",
            target_code="int target(void) { return 0; }",
            file_path="target.c",
            language="c",
        )

        command = runner._run_container.call_args.kwargs["command"]
        assert "-Dmain=vulnguard_target_main -c /tmp/workspace/target.c" in command
        assert "-fsanitize=address" in command
        assert "/tmp/vulnguard_target.o" in command

    def test_files_are_mounted_read_only_before_container_starts(self):
        runner = DockerRunner.__new__(DockerRunner)
        runner._client = MagicMock()
        container = runner._client.containers.create.return_value
        container.wait.return_value = {"StatusCode": 0}
        container.logs.return_value = b""

        result = runner._run_container("echo OK", extra_files={"/tmp/input.py": "pass"})

        assert result.success is True
        calls = [call[0] for call in container.method_calls]
        assert calls.index("start") < calls.index("wait")

        kwargs = runner._client.containers.create.call_args.kwargs
        assert any(
            volume == {"bind": "/vulnguard_inputs", "mode": "ro"}
            for volume in kwargs["volumes"].values()
        )
        assert kwargs["user"] == "65534:65534"
        assert kwargs["cap_drop"] == ["ALL"]
        assert kwargs["network_mode"] == "none"
        assert kwargs["read_only"] is True


@pytest.mark.docker
def test_sandbox_executes_as_unprivileged_user():
    if not check_docker_available():
        pytest.skip("Docker daemon is not available")

    runner = DockerRunner()
    result = runner._run_container(
        'test "$(id -u)" = 65534 && python3 --version && echo SANDBOX_OK'
    )

    assert result.success, result.combined_output
    assert "SANDBOX_OK" in result.stdout


@pytest.mark.docker
def test_python_exploit_imports_single_file_target():
    if not check_docker_available():
        pytest.skip("Docker daemon is not available")

    target_code = "def value():\n    return 'TARGET_IMPORTED'\n"
    runner = DockerRunner()
    result = runner.run_exploit(
        repo_root="",
        exploit_code="from sample_target import value\nprint(value())\n",
        target_code=target_code,
        file_path="sample_target.py",
        language="python",
    )

    assert result.success, result.combined_output
    assert "TARGET_IMPORTED" in result.stdout


@pytest.mark.docker
def test_c_exploit_links_target_with_existing_main():
    if not check_docker_available():
        pytest.skip("Docker daemon is not available")

    target_code = (
        "#include <stdio.h>\n"
        "void target(void) { puts(\"TARGET_LINKED\"); }\n"
        "int main(void) { return 0; }\n"
    )
    runner = DockerRunner()
    result = runner.run_exploit(
        repo_root="",
        exploit_code="void target(void); int main(void) { target(); return 0; }\n",
        target_code=target_code,
        file_path="sample_target.c",
        language="c",
    )

    assert result.success, result.combined_output
    assert "TARGET_LINKED" in result.stdout


@pytest.mark.docker
def test_c_buffer_overflow_is_detected_at_runtime():
    if not check_docker_available():
        pytest.skip("Docker daemon is not available")

    target_code = (
        "#include <string.h>\n"
        "void process_data(char *input) { char buffer[8]; strcpy(buffer, input); }\n"
        "int main(void) { return 0; }\n"
    )
    harness = (
        "#include <string.h>\n"
        "void process_data(char *input);\n"
        "int main(void) { char input[64]; memset(input, 'A', 63); "
        "input[63] = '\\0'; process_data(input); return 0; }\n"
    )
    runner = DockerRunner()
    result = runner.run_exploit(
        repo_root="",
        exploit_code=harness,
        target_code=target_code,
        file_path="vulnerable.c",
        language="c",
    )

    assert not result.success
    assert "VULNGUARD_EXECUTION_STARTED" in result.stdout
    assert "buffer-overflow" in result.stderr.lower()

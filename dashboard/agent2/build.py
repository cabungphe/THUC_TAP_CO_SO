"""Background Docker Compose build with streamed, secret-safe progress."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from .agent3 import process_lines
from .security import child_process_env, redact_secrets


COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_OVERRIDES = ("compose.override.yaml", "compose.override.yml",
                     "docker-compose.override.yaml", "docker-compose.override.yml")
_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def _source_path(root: Path, value: str, label: str) -> Path:
    """Resolve junctions/symlinks as well as '..' before accepting local inputs."""
    if (not isinstance(value, str) or not value or "://" in value
            or (":" in value and not (os.name == "nt" and re.match(r"^[A-Za-z]:[\\/]", value)))):
        raise ValueError(f"{label} phải là đường dẫn trong source đã chọn.")
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} nằm ngoài source đã chọn: {resolved}")
    return resolved


def source_compose_command(root: Path, command: list[str]) -> list[str]:
    """Never allow Compose discovery or inherited COMPOSE_FILE to select a source."""
    compose = next((root / name for name in COMPOSE_FILES if (root / name).is_file()), None)
    if compose is None:
        raise ValueError("Source cần có compose.yaml/yml hoặc docker-compose.yaml/yml tại thư mục gốc.")
    files = [compose]
    override = next((root / name for name in COMPOSE_OVERRIDES if (root / name).is_file()), None)
    if override:
        files.append(override)
    env_file = root / ".env"
    # An explicit empty env file also prevents discovery of a parent project's .env.
    env_path = str(_source_path(root, str(env_file), ".env")) if env_file.is_file() else os.devnull
    pinned = command + ["--project-directory", str(root), "--env-file", env_path]
    for path in files:
        pinned += ["--file", str(_source_path(root, str(path), "Compose file"))]
    return pinned


def _validate_source_config(job: BuildJob, lines: list[str]):
    try:
        config = json.loads("\n".join(lines))
        services = config["services"]
        if not isinstance(services, dict):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise RuntimeError("Không đọc được build context từ cấu hình Docker Compose.") from None
    builds = 0
    for name in job.services:
        service = services.get(name)
        if not isinstance(service, dict):
            raise RuntimeError("Cấu hình Docker Compose thiếu dịch vụ cần chạy.")
        build = service.get("build")
        if build is not None:
            if not isinstance(build, dict):
                raise RuntimeError("Cấu hình build Docker Compose không hợp lệ.")
            context = _source_path(job.root, build.get("context", "."), f"Build context ({name})")
            if not context.is_dir():
                raise ValueError(f"Build context ({name}) không tồn tại: {context}")
            if "dockerfile_inline" not in build:
                dockerfile = build.get("dockerfile", "Dockerfile")
                if not isinstance(dockerfile, str):
                    raise ValueError("Dockerfile không hợp lệ.")
                _source_path(job.root, str(context / dockerfile), f"Dockerfile ({name})")
            contexts = build.get("additional_contexts", {})
            if not isinstance(contexts, dict):
                raise ValueError("Additional build contexts không hợp lệ.")
            for value in contexts.values():
                # Image and same-project service inputs behave like Dockerfile FROM.
                if isinstance(value, str) and value.startswith(("docker-image://", "service:")):
                    continue
                _source_path(job.root, value, f"Additional build context ({name})")
            builds += 1
            job.emit(f"Build context ({name}): {context}")
        # A bind mount can hide the correctly built code with a different checkout.
        for volume in service.get("volumes", []):
            if isinstance(volume, dict) and volume.get("type") == "bind":
                _source_path(job.root, volume.get("source"), f"Bind mount ({name})")
    if not builds:
        raise ValueError("Compose không có dịch vụ build từ source đã chọn; chỉ có image sẵn.")


def docker_command() -> list[str]:
    executable = shutil.which("docker")
    if not executable and os.name == "nt":
        roots = (os.getenv("LOCALAPPDATA"), os.getenv("PROGRAMFILES"))
        candidates = (
            Path(roots[0]) / "Programs/DockerDesktop/resources/bin/docker.exe" if roots[0] else None,
            Path(roots[0]) / "Programs/Docker/Docker/resources/bin/docker.exe" if roots[0] else None,
            Path(roots[1]) / "Docker/Docker/resources/bin/docker.exe" if roots[1] else None,
        )
        executable = next((str(path) for path in candidates if path and path.is_file()), None)
    if not executable:
        raise RuntimeError("Không tìm thấy Docker CLI. Hãy cài Docker Desktop và mở Docker daemon.")
    return [executable, "compose"]


def docker_environment(executable: str | None = None) -> dict[str, str]:
    """Compose does not receive credentials used by either dashboard agent."""
    env = {key: value for key, value in child_process_env().items()
           if not key.upper().startswith("COMPOSE_")}
    if executable and Path(executable).is_absolute():
        # Docker Desktop keeps credential helpers beside docker.exe. A dashboard
        # process started before installation may still have an old PATH.
        env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
    env.update(COMPOSE_ANSI="never", NO_COLOR="1")
    return env


def _safe_reason(lines: list[str]) -> str:
    """Classify errors without ever repeating untrusted Docker output."""
    output = "\n".join(lines).lower()
    if "cannot connect to the docker daemon" in output or "error during connect" in output:
        return "Không kết nối được Docker daemon. Hãy mở Docker Desktop."
    if "permission denied" in output or "access is denied" in output:
        return "Docker từ chối quyền truy cập. Hãy kiểm tra quyền chạy Docker."
    if "port is already allocated" in output or "address already in use" in output:
        return "Cổng ứng dụng đang bị chiếm. Hãy kiểm tra container hoặc tiến trình đang dùng cổng."
    if "unauthorized" in output or "pull access denied" in output or "authentication required" in output:
        return "Không tải được image do Docker registry yêu cầu đăng nhập hoặc từ chối truy cập."
    if "failed to solve" in output or "executor failed" in output:
        return "Build image thất bại. Hãy kiểm tra Dockerfile và log Docker cục bộ."
    if "no configuration file provided" in output:
        return "Docker Compose không tìm thấy file cấu hình trong thư mục source."
    return "Hãy kiểm tra Dockerfile, compose file và log Docker cục bộ."


def _run_capture(command: list[str], root: Path, env: dict[str, str], timeout: int):
    stdout: deque[str] = deque(maxlen=1000)
    stderr: deque[str] = deque(maxlen=1000)
    exit_code = None
    for channel, line in process_lines(command, root, env, None, timeout):
        if channel == "exit":
            exit_code = line
        elif channel == "stdout":
            stdout.append(str(line)[:3000])
        else:
            stderr.append(str(line)[:3000])
    return exit_code, list(stdout), list(stderr)


def _parse_services(lines: list[str]) -> tuple[str, ...]:
    services = tuple(line.strip() for line in lines if line.strip())
    if not services or len(services) > 100 or any(not _SERVICE_NAME.fullmatch(s) for s in services):
        raise RuntimeError("Docker Compose trả về danh sách dịch vụ không hợp lệ.")
    return services


def _parse_ps(lines: list[str]) -> list[dict]:
    raw = "\n".join(lines).strip()
    if not raw:
        raise RuntimeError("Docker Compose không trả về trạng thái container.")
    try:
        parsed = json.loads(raw)
        rows = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        try:
            rows = [json.loads(line) for line in lines if line.strip()]
        except json.JSONDecodeError as exc:
            raise RuntimeError("Không đọc được trạng thái container từ Docker Compose.") from exc
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError("Docker Compose trả về trạng thái container không hợp lệ.")
    return rows


@dataclass
class BuildJob:
    root: Path
    command: list[str]
    timeout: int = 1200
    health_timeout: int = 90
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    state: str = "running"
    events: list[str] = field(default_factory=list)
    services: tuple[str, ...] = ()
    error: str = ""
    condition: threading.Condition = field(default_factory=threading.Condition, repr=False)
    done: threading.Event = field(default_factory=threading.Event, repr=False)

    def emit(self, message: str):
        message = redact_secrets(message)
        event = f"[{time.strftime('%H:%M:%S')}] {message[:1000]}"
        with self.condition:
            self.events.append(event)
            self.condition.notify_all()

    def stream(self):
        cursor = 0
        while True:
            with self.condition:
                self.condition.wait_for(lambda: cursor < len(self.events) or self.done.is_set())
                batch = self.events[cursor:]
                cursor += len(batch)
                done = self.done.is_set()
            yield from batch
            if done:
                return


def _verify_services(job: BuildJob, env: dict[str, str]):
    deadline = time.monotonic() + job.health_timeout
    previous = None
    while True:
        code, output, errors = _run_capture(job.command + ["ps", "--all", "--format", "json"],
                                            job.root, env, min(30, job.timeout))
        if code != 0:
            raise RuntimeError("Không kiểm tra được trạng thái dịch vụ. " + _safe_reason(errors + output))
        rows = _parse_ps(output)
        by_service = {str(row.get("Service", "")): row for row in rows}
        ready = 0
        pending = []
        for service in job.services:
            row = by_service.get(service)
            if not row:
                pending.append(service)
                continue
            state = str(row.get("State", "")).lower()
            health = str(row.get("Health", "")).lower()
            if state in {"dead", "exited", "paused", "removing"} or health == "unhealthy":
                raise RuntimeError("Một dịch vụ đã dừng hoặc healthcheck báo lỗi sau khi khởi động.")
            if state == "running" and health in {"", "none", "healthy"}:
                ready += 1
            else:
                pending.append(service)
        progress = (ready, len(job.services))
        if progress != previous:
            job.emit(f"Kiểm tra dịch vụ: {ready}/{len(job.services)} đang chạy và đạt healthcheck.")
            previous = progress
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Hết thời gian chờ dịch vụ khởi động hoặc đạt healthcheck.")
        time.sleep(min(2, remaining))


def run_build(job: BuildJob):
    try:
        job.command = source_compose_command(job.root, job.command)
        env = docker_environment(job.command[0])
        job.emit("Đang kiểm tra Docker Compose và danh sách dịch vụ…")
        job.emit(f"Source đã chọn: {job.root}")
        code, output, errors = _run_capture(job.command + ["config", "--services"],
                                            job.root, env, min(30, job.timeout))
        if code != 0:
            raise RuntimeError("Không đọc được cấu hình Docker Compose. " + _safe_reason(errors + output))
        job.services = _parse_services(output)
        code, output, errors = _run_capture(job.command + ["config", "--format", "json"],
                                            job.root, env, min(30, job.timeout))
        if code != 0:
            raise RuntimeError("Không đọc được build context. " + _safe_reason(errors + output))
        _validate_source_config(job, output)
        job.emit(f"Đã tìm thấy {len(job.services)} dịch vụ. Đang build image mới…")

        tail: deque[str] = deque(maxlen=80)
        last_step = 0
        starting = False
        exit_code = None
        for channel, line in process_lines(job.command + ["up", "--build", "-d"],
                                           job.root, env, None, job.timeout):
            if channel == "exit":
                exit_code = line
                continue
            line = str(line)
            tail.append(line[:3000])
            match = re.search(r"\bStep\s+(\d+)\s*/\s*(\d+)", line, re.I)
            if match:
                step = int(match.group(1))
                if step > last_step:
                    job.emit(f"Build image: bước {step}/{match.group(2)}.")
                    last_step = step
            elif (buildkit := re.search(r"^\s*#(\d+)\s", line)):
                step = int(buildkit.group(1))
                if step > last_step:
                    job.emit(f"Build image: bước {step}.")
                    last_step = step
            elif not starting and re.search(r"\b(?:Container|Creating|Starting|Started)\b", line, re.I):
                job.emit("Image đã build. Docker đang khởi động các dịch vụ…")
                starting = True
        if exit_code != 0:
            raise RuntimeError(f"Docker Compose build/start thất bại (exit {exit_code}). "
                               + _safe_reason(list(tail)))

        job.emit("Docker Compose hoàn tất. Đang kiểm tra container và healthcheck…")
        _verify_services(job, env)
        job.state = "succeeded"
        job.emit(f"Build & Run thành công: {len(job.services)} dịch vụ đang chạy.")
    except TimeoutError:
        job.state = "failed"
        job.error = "Docker Compose vượt thời gian cho phép."
        job.emit(job.error)
    except Exception as exc:
        job.state = "failed"
        # All expected errors are constructed from controlled text; never show raw Docker output.
        job.error = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else "Không thể chạy Docker Compose."
        job.emit("Build & Run chưa thành công: " + job.error)
    finally:
        with job.condition:
            job.done.set()
            job.condition.notify_all()


class BuildManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.jobs: dict[str, BuildJob] = {}

    def latest(self, root: str) -> BuildJob | None:
        with self.lock:
            return self.jobs.get(os.path.normcase(str(Path(root).resolve())))

    def start(self, root: str) -> BuildJob:
        path = Path(root).resolve(strict=True)
        if not path.is_dir() or not any((path / name).is_file() for name in COMPOSE_FILES):
            raise ValueError("Source cần có compose.yaml/yml hoặc docker-compose.yaml/yml tại thư mục gốc.")
        with self.lock:
            key = os.path.normcase(str(path))
            previous = self.jobs.get(key)
            if previous and not previous.done.is_set():
                return previous
            # Different checkouts can declare the same project/image/container names.
            # Keep their build+up sequences from racing against each other.
            if any(not other.done.is_set() for other in self.jobs.values()):
                raise ValueError("Một source khác đang build. Chờ hoàn tất rồi build source đã chọn.")
            job = BuildJob(path, docker_command())
            self.jobs[key] = job
            threading.Thread(target=run_build, args=(job,), daemon=True,
                             name=f"docker-build-{job.id}").start()
            return job

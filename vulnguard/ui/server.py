"""FastAPI backend for repository uploads and real-time VulnGuard scans."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import shutil
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from vulnguard.config import cfg
from vulnguard.ui.store import ScanStore
from vulnguard.evaluation import (
    EvaluationMetrics,
    LabelResult,
    KNOWN_VULN_FUNCTIONS,
    _compute_verdict_distribution,
    model_health_metrics_from_store,
    run_and_save_evaluation,
    write_evaluation_summary,
)
from vulnguard.agents.graph import run_pipeline

BENCHMARK_DIR = Path(__file__).resolve().parents[2] / "data" / "benchmarks"
EVALUATION_JSON = BENCHMARK_DIR / "evaluation.json"
EVALUATION_MD = BENCHMARK_DIR / "evaluation_summary.md"

logger = logging.getLogger(__name__)

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024


async def _safe_send(websocket: WebSocket, payload: dict[str, Any]) -> None:
    """Send a WS event, converting a closed client into WebSocketDisconnect.

    Scanning must not keep working (and keep writing rows) after the browser
    went away, and a failed send must not escape as an unhandled exception.
    """
    try:
        await websocket.send_json(payload)
    except (WebSocketDisconnect, RuntimeError, ConnectionError) as exc:
        logger.info("WebSocket client disconnected before an event could be sent")
        raise WebSocketDisconnect(code=1006) from exc
_MAX_EXTRACTED_BYTES = 50 * 1024 * 1024
_MAX_ARCHIVE_FILES = 500


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


async def _read_upload(file: UploadFile) -> bytes:
    chunks = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Upload exceeds the 25 MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _save_upload(content: bytes, filename: str, upload_root: Path) -> tuple[str, Path, list[Path], bool]:
    """Persist a source file or safely extract a ZIP repository."""
    from vulnguard.data.parser import supported_extensions

    if len(content) > _MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the 25 MB limit")

    upload_id = uuid4().hex
    target_root = upload_root / upload_id
    safe_name = Path(filename).name

    if Path(safe_name).suffix.lower() in supported_extensions():
        target_root.mkdir(parents=True)
        target = target_root / safe_name
        target.write_bytes(content)
        return upload_id, target_root, [target], False

    if not safe_name.lower().endswith(".zip"):
        raise ValueError("Unsupported source file; upload Python, C/C++, Java, JavaScript, or ZIP")

    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded ZIP archive is invalid") from exc

    members = [member for member in archive.infolist() if not member.is_dir()]
    if len(members) > _MAX_ARCHIVE_FILES:
        raise ValueError("ZIP archive contains too many files")
    if sum(member.file_size for member in members) > _MAX_EXTRACTED_BYTES:
        raise ValueError("ZIP archive expands beyond the 50 MB limit")

    for member in members:
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("ZIP archive may not contain symbolic links")
        if not _inside((target_root / member.filename).resolve(), target_root):
            raise ValueError("ZIP archive contains an unsafe path")

    target_root.mkdir(parents=True)
    with archive:
        for member in members:
            destination = (target_root / member.filename).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)

    children = list(target_root.iterdir())
    repo_root = children[0] if len(children) == 1 and children[0].is_dir() else target_root
    from vulnguard.data.parser import iter_source_files

    source_files = sorted(iter_source_files(repo_root))
    if not source_files:
        raise ValueError("ZIP repository contains no supported source files")
    return upload_id, repo_root, source_files, True


def _scan_paths(func: dict[str, Any], upload_root: Path) -> tuple[Path, Path | None]:
    file_path = Path(str(func.get("file_path", ""))).resolve()
    if not file_path.is_file() or not _inside(file_path, upload_root):
        raise ValueError("Scan target is outside the managed upload directory")

    repo_value = str(func.get("repo_root", ""))
    if not repo_value:
        return file_path, None
    repo_root = Path(repo_value).resolve()
    if not repo_root.is_dir() or not _inside(repo_root, upload_root) or not _inside(file_path, repo_root):
        raise ValueError("Repository root is invalid")
    return file_path, repo_root


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Folder upload contains an unsafe path")
    return path


def _function_payloads(source_files: list[Path], repo_root: Path, is_repository: bool) -> list[dict]:
    from vulnguard.data.parser import parse_file, read_source_file

    functions = []
    for source_path in source_files:
        code = read_source_file(source_path)
        relative_path = source_path.relative_to(repo_root).as_posix()
        for chunk in parse_file(str(source_path), code):
            functions.append(
                {
                    "id": f"{relative_path}:{chunk.function_name}",
                    "name": chunk.function_name,
                    "code": chunk.raw_source,
                    "language": chunk.language,
                    "file_path": str(source_path),
                    "relative_path": relative_path,
                    "repo_root": str(repo_root) if is_repository else "",
                    "start_byte": chunk.start_byte,
                    "end_byte": chunk.end_byte,
                    "imports": chunk.imports,
                    "callees": chunk.callees,
                }
            )
    return functions


def create_app(
    db_path: str | Path | None = None,
    upload_root: str | Path | None = None,
) -> FastAPI:
    """Create and configure the dashboard API."""
    scan_store = ScanStore(db_path or cfg.project_root / "data" / "vulnguard.db")
    managed_uploads = Path(upload_root or cfg.project_root / "data" / "uploads").resolve()
    managed_uploads.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="VulnGuard AI Dashboard",
        version="0.2.0",
        description="Real-time vulnerability detection and remediation dashboard",
    )
    app.state.scan_store = scan_store
    app.state.upload_root = managed_uploads
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/api/scan/status")
    async def scan_status():
        return JSONResponse({"scans": scan_store.list()})

    @app.get("/api/scan/verdict-distribution")
    async def get_verdict_distribution():
        return JSONResponse(scan_store.verdict_distribution())

    @app.get("/api/scan/successful-fixes")
    async def get_successful_fixes(limit: int = Query(20, ge=1, le=100)):
        try:
            return JSONResponse(scan_store.successful_fixes(limit=limit))
        except Exception as exc:
            # A genuine query/serialization failure must stay visible as a 5xx
            # (logged with its traceback) instead of masquerading as an empty list.
            logger.exception("Failed to load successful fixes")
            raise HTTPException(
                status_code=500, detail="Failed to load successful fixes"
            ) from exc

    @app.get("/api/results/{scan_id}")
    async def get_result(scan_id: str):
        result = scan_store.get(scan_id)
        if not result:
            return JSONResponse({"error": "Scan not found"}, status_code=404)
        return JSONResponse(result)

    @app.get("/api/metrics")
    async def get_metrics():
        return JSONResponse(scan_store.metrics())

    @app.post("/upload")
    async def upload_target(file: UploadFile = File(...)):
        content = await _read_upload(file)
        try:
            upload_id, repo_root, source_files, is_repository = _save_upload(
                content, file.filename or "upload.py", managed_uploads
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        functions = _function_payloads(source_files, repo_root, is_repository)
        return {
            "upload_id": upload_id,
            "repository": is_repository,
            "files_scanned": len(source_files),
            "functions": functions,
        }

    @app.get("/api/evaluation/model-health")
    async def get_model_health():
        return JSONResponse(model_health_metrics_from_store())

    _figures_dir = Path(__file__).resolve().parents[2] / "data" / "benchmarks"

    @app.get("/api/evaluation/health")
    async def get_evaluation_health():
        figure_files: list[str] = []
        for pattern in ("evaluation_*.png", "model_health_summary.png", "llm_usage_summary.png"):
            figure_files.extend(p.name for p in _figures_dir.glob(pattern))
        figure_files = list(dict.fromkeys(figure_files))
        health: dict[str, Any] = {
            "evaluation_json_exists": EVALUATION_JSON.exists(),
            "evaluation_summary_exists": EVALUATION_MD.exists(),
            "figures_dir": str(_figures_dir),
            "figures": figure_files,
            "figures_count": len(figure_files),
            "model_health": model_health_metrics_from_store(),
        }
        if EVALUATION_JSON.exists():
            try:
                payload = json.loads(EVALUATION_JSON.read_text(encoding="utf-8"))
                health["metrics"] = payload
                health["verdict_distribution"] = _evaluation_verdict_distribution(payload)
            except Exception as exc:
                health["metrics_error"] = str(exc)
        return JSONResponse(health)


    def _evaluation_verdict_distribution(payload: dict[str, Any]) -> dict[str, int]:
        patching = payload.get("patching", {})
        detection = payload.get("detection", {})
        distribution: dict[str, int] = {
            "PASS": int(patching.get("patches_validated", 0)),
            "FAIL": int(patching.get("patches_failed", 0)),
            "skipped": int(detection.get("false_negatives", 0)),
        }
        # Merge any extra verdict categories from the in-memory evaluation payload so
        # the UI analytics panel can show every recorded outcome, not only the standard
        # PASS/FAIL/skipped buckets.
        for key, value in patching.items():
            if key not in distribution and isinstance(value, int):
                distribution[key] = value
        return distribution

    @app.post("/api/evaluation/run")
    async def run_evaluation(request: dict[str, Any] | None = None):
        try:
            result = run_and_save_evaluation(request)
            return JSONResponse(result)
        except Exception as exc:
            logger.exception("Evaluation run failed")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/evaluation/figures/{filename}")
    async def get_figure(filename: str):
        figures_dir = BENCHMARK_DIR
        path = figures_dir / filename
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Figure not found")
        from fastapi.responses import FileResponse
        return FileResponse(path)

    @app.post("/upload/folder")
    async def upload_folder(
        files: list[UploadFile] = File(...),
        paths: list[str] = Form(...),
    ):
        if len(files) != len(paths):
            raise HTTPException(status_code=400, detail="Each folder file must include its relative path")
        if not files or len(files) > _MAX_ARCHIVE_FILES:
            raise HTTPException(status_code=400, detail="Folder contains too many files")

        upload_id = uuid4().hex
        repo_root = managed_uploads / upload_id
        repo_root.mkdir(parents=True)
        saved_files: list[Path] = []
        total_bytes = 0
        seen_paths: set[str] = set()

        try:
            for file, raw_path in zip(files, paths):
                relative = _safe_relative_path(raw_path)
                relative_key = relative.as_posix().lower()
                if relative_key in seen_paths:
                    raise ValueError("Folder upload contains duplicate paths")
                seen_paths.add(relative_key)

                content = await _read_upload(file)
                total_bytes += len(content)
                if total_bytes > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Folder upload exceeds the 50 MB limit")

                destination = repo_root.joinpath(*relative.parts).resolve()
                if not _inside(destination, repo_root):
                    raise ValueError("Folder upload contains an unsafe path")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                saved_files.append(destination)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        from vulnguard.data.parser import iter_source_files

        source_files = sorted(iter_source_files(repo_root))
        if not source_files:
            raise HTTPException(status_code=400, detail="Folder contains no supported source files")
        return {
            "upload_id": upload_id,
            "repository": True,
            "files_scanned": len(source_files),
            "files_uploaded": len(saved_files),
            "functions": _function_payloads(source_files, repo_root, True),
        }

    @app.websocket("/ws/scan")
    async def ws_scan(websocket: WebSocket):
        await websocket.accept()
        scan_id = uuid4().hex
        aggregate: dict[str, Any] = {"scan_id": scan_id, "pipeline_status": "STARTING"}
        stage = "startup"

        def persist() -> None:
            """Persist progress; a storage failure must not kill the stream."""
            aggregate["failed_stage"] = stage
            try:
                scan_store.save(scan_id, aggregate)
            except Exception:
                logger.exception("Failed to persist scan %s", scan_id)

        try:
            try:
                raw_request = await asyncio.wait_for(
                    websocket.receive_text(), timeout=30
                )
            except asyncio.TimeoutError as exc:
                raise ValueError(
                    "No scan request was received within 30 seconds"
                ) from exc
            func = json.loads(raw_request)
            file_path, repo_root = _scan_paths(func, managed_uploads)
            source_bytes = file_path.read_bytes()
            start_byte = int(func.get("start_byte", -1))
            end_byte = int(func.get("end_byte", -1))
            if not (0 <= start_byte < end_byte <= len(source_bytes)):
                raise ValueError("Function byte range is invalid")
            source_code = source_bytes[start_byte:end_byte].decode("utf-8", errors="replace")
            if source_code != func.get("code"):
                raise ValueError("Function source does not match the uploaded file")
            aggregate.update(
                function_id=func.get("id", "unknown"),
                file_path=str(file_path),
                repo_root=str(repo_root or ""),
            )
            persist()
            await _safe_send(websocket, 
                {
                    "type": "status",
                    "scan_id": scan_id,
                    "message": f"Starting scan for {func.get('name', 'function')}...",
                }
            )

            stage = "triage"
            try:
                from vulnguard.models.risk_scorer import RiskScorer

                scorer = RiskScorer()
                triage_result = scorer.score(source_code, func.get("language", "python"))
                score = triage_result.risk_score
                threshold = scorer.optimal_threshold
                is_high_risk = score >= threshold or triage_result.bypass_reason is not None
            except Exception as exc:
                logger.warning("ML triage unavailable; routing to agents: %s", exc)
                score = 100.0
                threshold = cfg.triage.risk_threshold
                is_high_risk = True

            aggregate.update(risk_score=score, pipeline_status="TRIAGE")
            persist()
            await _safe_send(websocket, 
                {
                    "type": "triage_result",
                    "scan_id": scan_id,
                    "score": round(score, 1),
                    "threshold": threshold,
                    "is_high_risk": is_high_risk,
                }
            )

            if not is_high_risk:
                aggregate.update(pipeline_status="COMPLETE", vulnerability_found=False)
                persist()
                await _safe_send(websocket, 
                    {"type": "complete", "scan_id": scan_id, "message": "Low risk; agent analysis skipped."}
                )
                return

            stage = "context"
            from vulnguard.agents.graph import compile_graph
            from vulnguard.agents.state import initial_state
            from vulnguard.data.context_gatherer import gather_context

            context = gather_context(
                source_code,
                file_path=file_path,
                repo_root=repo_root or file_path.parent,
                language=func.get("language", "python"),
            )
            await _safe_send(websocket, 
                {
                    "type": "context_result",
                    "scan_id": scan_id,
                    "imports": len(context.imports),
                    "callees": len(context.callee_signatures),
                    "warnings": context.warnings,
                    "token_count": context.token_count,
                }
            )

            state = initial_state(
                function_id=func.get("id", "unknown"),
                code=source_code,
                language=func.get("language", "python"),
                risk_score=score,
                context_bundle=context.to_dict(),
                file_path=str(file_path),
                repo_root=str(repo_root or ""),
                start_byte=start_byte,
                end_byte=end_byte,
            )
            aggregate.update(state)
            graph_app = compile_graph()
            stage = "agents"
            async for step in graph_app.astream(state):
                for node_name, node_state in step.items():
                    stage = node_name
                    aggregate.update(node_state)
                    aggregate["last_agent"] = node_name
                    persist()
                    await _safe_send(websocket, 
                        {
                            "type": "agent_update",
                            "scan_id": scan_id,
                            "agent": node_name,
                            "state": node_state,
                        }
                    )

            status = aggregate.get("pipeline_status")
            if status == "RED_COMPLETE" and not aggregate.get("vulnerability_found"):
                aggregate["pipeline_status"] = "COMPLETE"
            elif status == "RED_ERROR":
                # A Red Agent generation/parse failure is recorded as an
                # internal error, never as a clean "no vulnerability" scan.
                aggregate["pipeline_status"] = "FAILED"
                aggregate["judge_verdict"] = "RED_AGENT_ERROR"
            elif status in {"STARTING", "TRIAGE", "RED_COMPLETE", "RED", "BLUE", "JUDGE", "RETRY"}:
                # The stream ended without a terminal judge verdict — never
                # report that as a completed, validated scan.
                logger.warning(
                    "Scan %s ended without a terminal verdict (status=%s)",
                    scan_id,
                    status,
                )
                aggregate["pipeline_status"] = "FAILED"
                aggregate["judge_verdict"] = "PIPELINE_INCOMPLETE"
            stage = "complete"
            aggregate["completed_at"] = datetime.now(timezone.utc).isoformat()
            persist()
            await _safe_send(
                websocket,
                {
                    "type": "complete",
                    "scan_id": scan_id,
                    "pipeline_status": aggregate.get("pipeline_status"),
                    "judge_verdict": aggregate.get("judge_verdict"),
                },
            )
        except WebSocketDisconnect:
            logger.info("Scan %s stopped: client disconnected during %s", scan_id, stage)
            aggregate["pipeline_status"] = "DISCONNECTED"
            aggregate["failed_stage"] = stage
            try:
                scan_store.save(scan_id, aggregate)
            except Exception:
                logger.exception("Failed to persist disconnected scan %s", scan_id)
        except Exception as exc:
            # The full traceback stays in the server log; the client gets the
            # failed stage and a concise, actionable message.
            logger.exception("Error in ws_scan (stage=%s)", stage)
            aggregate.update(
                pipeline_status="ERROR",
                error_logs=str(exc)[:2000],
                failed_stage=stage,
            )
            try:
                scan_store.save(scan_id, aggregate)
            except Exception:
                logger.exception("Failed to persist failed scan %s", scan_id)
            try:
                await _safe_send(
                    websocket,
                    {
                        "type": "error",
                        "scan_id": scan_id,
                        "stage": stage,
                        "function_id": aggregate.get("function_id"),
                        "message": str(exc)[:500],
                    },
                )
            except WebSocketDisconnect:
                logger.info("Could not deliver the scan error event; client is gone")

    return app

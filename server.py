"""
SentinelAI — Web API Server
FastAPI backend that wraps all SentinelAI modules.
Serves the web frontend and provides WebSocket streaming for live audits.

Usage:
    python server.py
    # Then open http://localhost:8765
"""

import os
import sys
import json
import asyncio
import threading
import uuid
import traceback
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import SentinelAI modules
from key_manager import APIKeyManager
from repo_resolver import resolve_target
from scanners.gitleaks import GitleaksScanner
from rag_builder import build_rag_system
from context_builder import build_project_context
from ai_analyzer import analyze_codebase_stream, generate_suggestions
from compliance_profiles import get_available_profiles, get_profile
from report_exporter import export_to_html, get_export_capabilities
from patch_generator import generate_patches, save_patches
from ci_reporter import format_json_report, determine_exit_code
from history_tracker import save_audit, get_audit_history, get_audit_detail, get_trend_data, get_most_common_vulnerabilities
from sbom_generator import generate_sbom, save_sbom, format_sbom_summary

app = FastAPI(title="SentinelAI", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Global state
key_manager = APIKeyManager()

# Store audit results for post-audit features (chat, patches, export, sbom)
audit_sessions = {}  # session_id -> {report, suggestions, raw_code, collection, target, resolved_path, secrets}


# ─── REST Endpoints ───

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main web UI."""
    index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>Frontend not found. Place index.html in frontend/</h1>")


@app.post("/api/keys")
async def add_key(data: dict):
    """Add an API key."""
    key = data.get("key", "").strip()
    if not key:
        raise HTTPException(400, "Key cannot be empty")
    key_manager.add_key(key)
    return {"count": key_manager.count(), "message": "Key added"}


@app.get("/api/keys/count")
async def key_count():
    return {"count": key_manager.count()}


@app.get("/api/compliance")
async def list_compliance():
    """List available compliance frameworks."""
    profiles = get_available_profiles()
    return {"profiles": [{"key": k, "name": v} for k, v in profiles.items()]}


@app.get("/api/history")
async def api_history(target: str = "", limit: int = 20):
    """Get audit history."""
    audits = get_audit_history(target=target if target else None, limit=limit)
    return {"audits": audits}


@app.get("/api/history/{audit_id}")
async def api_history_detail(audit_id: str):
    """Get detail for a specific audit."""
    detail = get_audit_detail(audit_id)
    if not detail:
        raise HTTPException(404, "Audit not found")
    # Remove large markdown fields for API response
    detail.pop("report_md", None)
    detail.pop("suggestions_md", None)
    return detail


@app.get("/api/trend/{target}")
async def api_trend(target: str, limit: int = 10):
    """Get trend data for a target."""
    return get_trend_data(target, limit=limit)


@app.get("/api/common-vulns")
async def api_common_vulns(limit: int = 10):
    return {"vulnerabilities": get_most_common_vulnerabilities(limit=limit)}


@app.post("/api/sbom/{session_id}")
async def api_sbom(session_id: str):
    """Generate SBOM for a completed audit."""
    session = audit_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found. Run an audit first.")
    sbom = generate_sbom(session["resolved_path"])
    path = save_sbom(sbom)
    summary = format_sbom_summary(sbom)
    return {"path": path, "summary": summary, "component_count": len(sbom.get("components", []))}


@app.post("/api/patches/{session_id}")
async def api_patches(session_id: str):
    """Generate patches for a completed audit."""
    session = audit_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    patches = generate_patches(
        session["report"], session["raw_code"], key_manager,
        log_callback=lambda msg: None
    )
    if patches:
        output_dir = save_patches(patches)
        return {"count": len(patches), "output_dir": output_dir,
                "patches": [{"file": p["file"], "severity": p["severity"]} for p in patches]}
    return {"count": 0, "patches": []}


@app.post("/api/export/{session_id}")
async def api_export(session_id: str):
    """Export the report as HTML."""
    session = audit_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    path = export_to_html(session["report"], session["suggestions"], session["target"])
    return {"path": path, "format": "html"}


@app.post("/api/chat/{session_id}")
async def api_chat(session_id: str, data: dict):
    """Chat with a completed audit."""
    session = audit_sessions.get(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    question = data.get("question", "").strip()
    if not question:
        raise HTTPException(400, "Question cannot be empty")

    from chat_engine import AuditChatEngine
    engine = AuditChatEngine(
        collection=session["collection"],
        raw_code=session["raw_code"],
        report=session["report"],
        key_manager=key_manager,
        history=session.get("chat_history", [])
    )

    answer = ""
    for chunk in engine.ask(question):
        answer += chunk

    session.setdefault("chat_history", []).append({"role": "user", "content": question})
    session["chat_history"].append({"role": "assistant", "content": answer})

    return {"answer": answer}


# ─── WebSocket Streaming Audit ───

@app.websocket("/ws/audit")
async def ws_audit(websocket: WebSocket):
    """
    WebSocket endpoint for streaming audits.
    Client sends: { "target": "...", "compliance": "owasp" }
    Server streams: { "type": "phase|log|report|suggestions|complete|error", "data": "..." }
    """
    await websocket.accept()

    try:
        init_msg = await websocket.receive_json()
        target = init_msg.get("target", "").strip()
        compliance = init_msg.get("compliance", "").strip()

        if not target:
            await websocket.send_json({"type": "error", "data": "Target is required"})
            await websocket.close()
            return

        if key_manager.count() == 0:
            await websocket.send_json({"type": "error", "data": "No API keys configured. Add a key first."})
            await websocket.close()
            return

        session_id = str(uuid.uuid4())[:8]

        async def send(msg_type, data):
            try:
                await websocket.send_json({"type": msg_type, "data": data})
            except Exception:
                pass

        # Run audit in a thread to not block the event loop
        loop = asyncio.get_event_loop()

        def run_audit_sync():
            """Run the full audit pipeline synchronously in a thread."""
            results = {"error": None}

            try:
                # Phase 0: Resolve target
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 0, "name": "Resolving Target"}), loop)

                def log_cb(msg):
                    asyncio.run_coroutine_threadsafe(send("log", msg), loop)

                resolved_path = resolve_target(target, log_callback=log_cb)
                asyncio.run_coroutine_threadsafe(send("log", f"Resolved to: {resolved_path}"), loop)

                # Phase 1: Static Analysis
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 1, "name": "Static Analysis (Gitleaks)"}), loop)
                try:
                    scanner = GitleaksScanner(resolved_path)
                    secrets = scanner.run()
                except Exception as e:
                    secrets = []
                    asyncio.run_coroutine_threadsafe(send("log", f"Gitleaks error: {e}"), loop)

                secrets_count = len(secrets)
                asyncio.run_coroutine_threadsafe(
                    send("log", f"Found {secrets_count} potential secrets" if secrets_count else "No secrets found"),
                    loop
                )

                # Phase 2: RAG Context
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 2, "name": "Building Vector Index"}), loop)
                collection = build_rag_system(resolved_path, key_manager, log_callback=log_cb)

                # Phase 3: Code Ingestion
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 3, "name": "Code Ingestion"}), loop)
                raw_code = build_project_context(resolved_path)
                code_size_kb = len(raw_code) / 1024
                asyncio.run_coroutine_threadsafe(
                    send("log", f"Ingested {code_size_kb:.1f} KB of source code"),
                    loop
                )

                # Phase 4: Deep Audit
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 4, "name": "6-Phase Deep Security Audit"}), loop)
                findings_str = json.dumps(secrets, indent=2) if secrets else "No static analysis findings."

                full_report = ""
                for chunk in analyze_codebase_stream(collection, findings_str, key_manager, raw_code=raw_code, compliance=compliance):
                    full_report += chunk
                    asyncio.run_coroutine_threadsafe(send("report_chunk", chunk), loop)

                # Phase 5: Suggestions
                asyncio.run_coroutine_threadsafe(send("phase", {"phase": 5, "name": "Generating Remediation Plan"}), loop)
                suggestions = generate_suggestions(full_report, key_manager)
                asyncio.run_coroutine_threadsafe(send("suggestions", suggestions), loop)

                # Save to history
                try:
                    audit_id = save_audit(
                        target=target, report=full_report, suggestions=suggestions,
                        compliance=compliance, secrets_count=secrets_count, code_size_kb=code_size_kb
                    )
                    asyncio.run_coroutine_threadsafe(send("log", f"Saved to history (ID: {audit_id})"), loop)
                except Exception:
                    pass

                # Store session for post-audit features
                audit_sessions[session_id] = {
                    "report": full_report,
                    "suggestions": suggestions,
                    "raw_code": raw_code,
                    "collection": collection,
                    "target": target,
                    "resolved_path": resolved_path,
                    "secrets": secrets,
                    "chat_history": [],
                }

                asyncio.run_coroutine_threadsafe(
                    send("complete", {"session_id": session_id, "audit_id": audit_id if 'audit_id' in dir() else ""}),
                    loop
                )

            except Exception as e:
                tb = traceback.format_exc()
                asyncio.run_coroutine_threadsafe(send("error", f"{e}\n{tb}"), loop)

        # Run in thread
        thread = threading.Thread(target=run_audit_sync, daemon=True)
        thread.start()

        # Keep connection alive while audit runs
        while thread.is_alive():
            await asyncio.sleep(0.5)

        # Give a moment for final messages
        await asyncio.sleep(1)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "data": str(e)})
        except Exception:
            pass


if __name__ == "__main__":
    print("\n  SentinelAI Web Server")
    print("  http://localhost:8765\n")
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="info")

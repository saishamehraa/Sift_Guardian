from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI

from utils import load_mock_data, load_process_list_with_real_fallback, load_timeline_with_real_fallback

BASE_PATH = Path(__file__).resolve().parent
DATA = load_mock_data(BASE_PATH)

app = FastAPI(
    title="SIFT-Guardian MCP Server",
    description="Read-only forensic function server for incident response agents.",
    version="0.1.0",
)


@app.get("/get_process_list")
def get_process_list() -> Dict[str, List[Dict[str, Any]]]:
    return {"process_list": load_process_list_with_real_fallback(BASE_PATH, DATA)}


@app.get("/extract_timeline")
def extract_timeline() -> Dict[str, List[Dict[str, Any]]]:
    return {"timeline": load_timeline_with_real_fallback(BASE_PATH, DATA)}


@app.get("/get_login_events")
def get_login_events() -> Dict[str, List[Dict[str, Any]]]:
    return {"login_events": DATA["login_events"]}


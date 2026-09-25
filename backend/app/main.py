from collections import Counter, defaultdict
from pathlib import Path
import json
import os
import subprocess
import tempfile
import uuid

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Deep Packet Analyzer API", version="1.0.0")
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_SIZE", os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024))))
MAX_ANALYSES = int(os.getenv("MAX_ANALYSES", "8"))
ANALYZER_TIMEOUT = float(os.getenv("ANALYZER_TIMEOUT", "180"))
ANALYSES: dict[str, dict] = {}
ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "frontend"


@app.get("/api/health")
def health():
    return {"status": "ok"}


def _binary() -> str:
    explicit = os.getenv("ANALYZER_PATH") or os.getenv("DPI_ANALYZER")
    candidates = [Path(explicit)] if explicit else []
    candidates += [ROOT / "build" / "dpi_web_analyzer", ROOT / "build" / "Release" / "dpi_web_analyzer.exe", ROOT / "build" / "dpi_web_analyzer.exe"]
    for path in candidates:
        if path and path.is_file():
            return str(path)
    raise HTTPException(503, "Analyzer binary is missing. Build target dpi_web_analyzer with CMake.")


@app.post("/api/analyses", status_code=201)
async def upload_capture(file: UploadFile = File(...)):
    name = (file.filename or "capture.pcap").replace("\\", "/").split("/")[-1]
    if Path(name).suffix.lower() != ".pcap":
        raise HTTPException(400, "This analyzer currently supports .pcap files only. PCAPNG support is not available yet.")
    content = await file.read(MAX_UPLOAD + 1)
    if not content or len(content) > MAX_UPLOAD:
        raise HTTPException(413 if len(content) > MAX_UPLOAD else 400, f"The file is empty or exceeds the {MAX_UPLOAD // (1024 * 1024)} MB upload limit.")
    if len(content) < 24 or content[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise HTTPException(400, "The uploaded file could not be parsed as a valid PCAP capture.")
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(suffix=".pcap", prefix="dpi-upload-")
        os.close(fd)
        Path(temp_path).write_bytes(content)
        proc = subprocess.run([_binary(), temp_path], capture_output=True, text=True, timeout=ANALYZER_TIMEOUT, shell=False)
        if proc.returncode:
            raise HTTPException(422, "The uploaded file could not be parsed as a valid PCAP capture.")
        packets = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    except subprocess.TimeoutExpired:
        raise HTTPException(408, "Analysis took too long. Try a smaller capture.")
    except (OSError, json.JSONDecodeError):
        raise HTTPException(422, "The uploaded file could not be parsed as a valid PCAP capture.")
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
        await file.close()
    required = {"number", "timestamp", "length", "transport", "application", "src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "dst_mac", "ttl", "tcp_flags", "host", "payload_length"}
    if any(not isinstance(p, dict) or not required.issubset(p) or
           not isinstance(p["number"], int) or not isinstance(p["timestamp"], (int, float)) or
           not isinstance(p["length"], int) or not isinstance(p["src_port"], int) or
           not isinstance(p["dst_port"], int) or not isinstance(p["transport"], str) or
           not isinstance(p["application"], str) or not isinstance(p["src_ip"], str) or
           not isinstance(p["dst_ip"], str) for p in packets):
        raise HTTPException(422, "The analyzer returned incomplete packet data. Please retry with a valid PCAP capture.")
    if not packets:
        raise HTTPException(422, "The uploaded file could not be parsed as a valid PCAP capture.")
    result = _summarize(name, packets)
    analysis_id = str(uuid.uuid4())
    ANALYSES[analysis_id] = result
    while len(ANALYSES) > MAX_ANALYSES:
        ANALYSES.pop(next(iter(ANALYSES)))
    return {"analysis_id": analysis_id, "summary": result["summary"]}


def _summarize(name, packets):
    first = min(p["timestamp"] for p in packets)
    last = max(p["timestamp"] for p in packets)
    apps, transports, srcs, dsts, ports = Counter(), Counter(), Counter(), Counter(), Counter()
    flow_map = {}
    for p in packets:
        apps[p["application"]] += 1
        transports[p["transport"]] += 1
        srcs[p["src_ip"]] += 1
        dsts[p["dst_ip"]] += 1
        if p["src_port"]: ports[str(p["src_port"])] += 1
        if p["dst_port"]: ports[str(p["dst_port"])] += 1
        key = (p["src_ip"], p["dst_ip"], p["src_port"], p["dst_port"], p["transport"])
        flow = flow_map.setdefault(key, {"src_ip": key[0], "dst_ip": key[1], "src_port": key[2], "dst_port": key[3], "transport": key[4], "packets": 0, "bytes": 0, "application": p["application"]})
        flow["packets"] += 1; flow["bytes"] += p["length"]
    summary = {"filename": name, "total_packets": len(packets), "total_bytes": sum(p["length"] for p in packets), "duration_seconds": max(0, last-first), "unique_sources": len(set(srcs)-{""}), "unique_destinations": len(set(dsts)-{""}), "tcp_packets": transports["TCP"], "udp_packets": transports["UDP"], "protocols": dict(apps)}
    timeline = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for p in packets:
        t = int(p["timestamp"] - first); timeline[t]["packets"] += 1; timeline[t]["bytes"] += p["length"]
    return {"summary": summary, "packets": packets, "flows": sorted(flow_map.values(), key=lambda x:x["packets"], reverse=True), "charts": {"protocols": [{"name":k,"value":v} for k,v in apps.most_common()], "sources": [{"name":k or "(unavailable)","value":v} for k,v in srcs.most_common(8)], "destinations": [{"name":k or "(unavailable)","value":v} for k,v in dsts.most_common(8)], "ports": [{"name":k,"value":v} for k,v in ports.most_common(8)], "timeline": [{"second":k,"packets":v["packets"],"bytes":v["bytes"]} for k,v in sorted(timeline.items())]}}


def _get(analysis_id):
    if analysis_id not in ANALYSES: raise HTTPException(404, "Analysis not found or expired.")
    return ANALYSES[analysis_id]


@app.get("/api/analyses/{analysis_id}")
def analysis(analysis_id: str):
    item = _get(analysis_id)
    return {k:v for k,v in item.items() if k != "packets"}


@app.get("/api/analyses/{analysis_id}/packets")
def packets(analysis_id: str, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), search: str = "", protocol: str = "", src_ip: str = "", dst_ip: str = "", port: str = "", sort_by: str = "number", order: str = "asc"):
    rows = _get(analysis_id)["packets"]
    protocol_key = protocol.casefold()
    rows = [p for p in rows if
            (not search or search.casefold() in json.dumps(p).casefold()) and
            (not protocol_key or protocol_key in {p["application"].casefold(), p["transport"].casefold()}) and
            (not src_ip or src_ip.casefold() in p["src_ip"].casefold()) and
            (not dst_ip or dst_ip.casefold() in p["dst_ip"].casefold()) and
            (not port or port in (str(p["src_port"]), str(p["dst_port"]))) ]
    if sort_by not in {"number", "timestamp", "src_ip", "dst_ip", "transport", "application", "length", "src_port", "dst_port"}:
        raise HTTPException(400, "Unsupported sort field.")
    rows.sort(key=lambda p: p.get(sort_by, 0), reverse=order.lower() == "desc")
    start = (page-1)*page_size
    return {"items": rows[start:start+page_size], "total": len(rows), "page": page, "page_size": page_size}


@app.get("/")
def home(): return FileResponse(WEB / "index.html")


@app.get("/analysis/{analysis_id}")
def analysis_page(analysis_id: str):
    _get(analysis_id)
    return FileResponse(WEB / "index.html")

app.mount("/static", StaticFiles(directory=WEB), name="static")

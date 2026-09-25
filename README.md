# Deep Packet Analyzer

A web-based Deep Packet Inspection and network traffic analysis system powered by a C++ packet analyzer and FastAPI.

## Overview

Upload a classic Ethernet PCAP to inspect packet metadata, directional flows, protocol categories, and traffic summaries through a static browser UI. Analysis uses the existing C++ packet parser and DPI extractors through a small JSON adapter.

## Features

- PCAP upload with a configurable size limit and clear unsupported-format errors.
- Overview metrics, protocol distribution, traffic timeline, and endpoint/port rankings.
- Searchable, filterable, sortable, paginated packet explorer with packet detail view.
- Directional flow table and protocol category breakdown.
- Same-origin static frontend, API, and analyzer in one service.

## Screenshots

Screenshots are not included yet. Capture the upload screen, Overview after analyzing `test_dpi.pcap`, Packet Explorer, Flows, and Protocols views; save them under `docs/images/` and add the resulting images here.

## Architecture

```text
PCAP
  ↓
Web UI
  ↓
FastAPI
  ↓
C++ DPI Adapter
  ↓
Existing Packet Parser / DPI Extractors
  ↓
Structured Analysis Results
```

FastAPI serves the static UI and invokes the analyzer with a unique temporary capture path. The existing CLI engine and its blocking behavior are separate from this read-only web adapter.

## Tech Stack

- C++17, CMake
- Python, FastAPI, Uvicorn
- Static HTML, CSS, and JavaScript (no frontend framework or package install)
- Docker Compose for a single-container deployment

## Running Locally

Prerequisites: CMake, a C++17 compiler, and Python 3.10 or newer.

Build the analyzer from the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target dpi_web_analyzer
```

Create a virtual environment, install `backend/requirements.txt`, then start the service from the `backend/` directory. Set `ANALYZER_PATH` to the built executable if it is not at a default build path. For example, in PowerShell with MinGW:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
$env:ANALYZER_PATH = (Resolve-Path .\build\dpi_web_analyzer.exe).Path
cd backend
..\.venv\Scripts\python.exe -m app.run
```

Open `http://127.0.0.1:8000`. The server reads `HOST` (default `0.0.0.0`) and `PORT` (default `8000`). Upload `test_dpi.pcap` to explore the sample capture.

## Docker

Docker builds the C++ adapter in a separate stage and serves the frontend and API from one container. Run from the repository root:

```sh
docker compose up --build
```

The service listens on port 8000 by default. `PORT`, `MAX_UPLOAD_SIZE`, `ANALYZER_TIMEOUT`, and `MAX_ANALYSES` can be set in the environment. `GET /api/health` is used for the container health check. Docker execution has not been verified in the development environment.

## Testing

Install backend requirements, build the analyzer, then run from the repository root:

```sh
set DPI_ANALYZER=build\dpi_web_analyzer.exe
python -m pytest backend/tests -q
node --check frontend/app.js
```

Set `DPI_ANALYZER` to the platform-specific executable path for the real C++ integration test (PowerShell: `$env:DPI_ANALYZER = (Resolve-Path .\build\dpi_web_analyzer.exe).Path`; POSIX shell: `DPI_ANALYZER="$PWD/build/dpi_web_analyzer"`). Then run `python -m pytest backend/tests -q` and `node --check frontend/app.js` from the repository root.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
| POST | `/api/analyses` | Upload a multipart PCAP (`file`) |
| GET | `/api/analyses/{id}` | Summary, flows, and chart data |
| GET | `/api/analyses/{id}/packets` | Paginated packet rows and filters |
| GET | `/analysis/{id}` | Analysis dashboard deep link |

Interactive API documentation is available at `/docs`.

## Project Structure

```text
backend/app/       FastAPI routes and environment-configured server entry point
backend/tests/     API, concurrency, security regression, and C++ integration tests
frontend/          Static dashboard
include/, src/     Existing C++ parser and DPI engine
test_dpi.pcap      Sample capture used for integration verification
```

## Limitations

- Classic Ethernet **PCAP is supported**; **PCAPNG is unsupported**.
- **IPv4 is supported**; **IPv6 is currently unsupported**.
- **TCP stream reassembly is not implemented**; TLS SNI and other payload-derived fields require their relevant data in one packet.
- VLAN-tagged traffic and non-Ethernet link types are not supported by the current parser.
- Results are held in process memory and expire on restart or cache eviction.

## Security Considerations

Uploads are size-limited, written to unique temporary files, and removed after analysis. The analyzer runs as an argument-list subprocess without a shell, with a timeout and sanitized errors. Packet-derived text is escaped by the UI. CORS is not enabled because the UI and API use the same origin. Before public deployment, put the service behind authentication and HTTPS and apply resource limits and request quotas; this demo has no user accounts or persistent result store.

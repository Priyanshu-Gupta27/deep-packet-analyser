import struct
import pytest
import json
import subprocess
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app, ANALYSES

client = TestClient(app)
PCAP = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

def test_health():
    assert client.get('/api/health').json() == {'status': 'ok'}

def test_rejects_extension():
    response = client.post('/api/analyses', files={'file': ('bad.pcapng', PCAP)})
    assert response.status_code == 400
    assert response.json()['detail'] == 'This analyzer currently supports .pcap files only. PCAPNG support is not available yet.'

def test_rejects_malformed():
    assert client.post('/api/analyses', files={'file': ('bad.pcap', b'not a capture')}).status_code == 400

def test_rejects_oversized_upload(monkeypatch):
    monkeypatch.setattr('app.main.MAX_UPLOAD', 23)
    assert client.post('/api/analyses', files={'file': ('large.pcap', PCAP)}).status_code == 413

def test_valid_upload(monkeypatch):
    packet = {'number': 1, 'timestamp': 1.0, 'length': 60, 'transport': 'TCP', 'application': 'HTTP', 'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8', 'src_port': 123, 'dst_port': 80, 'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:02', 'ttl': 64, 'tcp_flags': 'SYN', 'host': '', 'payload_length': 0}
    paths = []
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    def run(args, **kwargs):
        paths.append(args[1])
        assert kwargs.get('shell') is False
        return subprocess.CompletedProcess(args, 0, json.dumps(packet)+'\n', '')
    monkeypatch.setattr(subprocess, 'run', run)
    response = client.post('/api/analyses', files={'file': ('sample.pcap', PCAP)})
    assert response.status_code == 201
    key = response.json()['analysis_id']
    result = client.get(f'/api/analyses/{key}').json()
    assert result['summary']['total_packets'] == 1
    assert result['flows'][0]['packets'] == 1
    assert result['charts']['protocols'] == [{'name': 'HTTP', 'value': 1}]
    assert result['charts']['timeline'][0]['packets'] == 1
    assert client.get(f'/analysis/{key}').status_code == 200
    assert client.get(f'/api/analyses/{key}/packets').json()['total'] == 1
    assert len(paths) == 1 and not Path(paths[0]).exists()

def test_temp_files_are_unique_between_analyses(monkeypatch):
    packet = {'number': 1, 'timestamp': 1.0, 'length': 60, 'transport': 'TCP', 'application': 'HTTP', 'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8', 'src_port': 123, 'dst_port': 80, 'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:02', 'ttl': 64, 'tcp_flags': 'SYN', 'host': '', 'payload_length': 0}
    paths = []
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    def run(args, **kwargs):
        paths.append(args[1])
        return subprocess.CompletedProcess(args, 0, json.dumps(packet)+'\n', '')
    monkeypatch.setattr(subprocess, 'run', run)
    first = client.post('/api/analyses', files={'file': ('first.pcap', PCAP)}).json()
    second = client.post('/api/analyses', files={'file': ('second.pcap', PCAP)}).json()
    assert first['analysis_id'] != second['analysis_id']
    assert client.get(f"/api/analyses/{first['analysis_id']}").json()['summary']['filename'] == 'first.pcap'
    assert client.get(f"/api/analyses/{second['analysis_id']}").json()['summary']['filename'] == 'second.pcap'
    assert len(set(paths)) == 2 and not any(Path(p).exists() for p in paths)

def test_concurrent_uploads_are_isolated(monkeypatch):
    packet = {'number': 1, 'timestamp': 1.0, 'length': 60, 'transport': 'TCP', 'application': 'HTTP', 'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8', 'src_port': 123, 'dst_port': 80, 'src_mac': '00:00:00:00:00:01', 'dst_mac': '00:00:00:00:00:02', 'ttl': 64, 'tcp_flags': 'SYN', 'host': '', 'payload_length': 0}
    paths = []
    paths_lock = Lock()
    overlap = Barrier(2)
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    def run(args, **kwargs):
        with paths_lock:
            paths.append(args[1])
        overlap.wait(timeout=10)
        return subprocess.CompletedProcess(args, 0, json.dumps(packet)+'\n', '')
    monkeypatch.setattr(subprocess, 'run', run)
    def upload(name):
        return client.post('/api/analyses', files={'file': (name, PCAP)})
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(upload, ('first.pcap', 'second.pcap')))
    assert all(response.status_code == 201 for response in responses)
    results = [response.json() for response in responses]
    assert len({result['analysis_id'] for result in results}) == 2
    assert len(paths) == 2 and len(set(paths)) == 2
    assert all(not Path(path).exists() for path in paths)
    names = {client.get(f"/api/analyses/{result['analysis_id']}").json()['summary']['filename'] for result in results}
    assert names == {'first.pcap', 'second.pcap'}

def test_analyzer_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 4, '', 'C:\\private\\path\\capture.pcap failed'))
    response = client.post('/api/analyses', files={'file': ('bad.pcap', PCAP)})
    assert response.status_code == 422
    assert 'private' not in response.text and response.json()['detail'] == 'The uploaded file could not be parsed as a valid PCAP capture.'

def test_malformed_analyzer_json_is_sanitized(monkeypatch):
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 0, 'not json\n', ''))
    response = client.post('/api/analyses', files={'file': ('bad-output.pcap', PCAP)})
    assert response.status_code == 422 and 'Traceback' not in response.text

def test_cors_is_not_open():
    response = client.get('/api/health', headers={'Origin': 'https://untrusted.example'})
    assert 'access-control-allow-origin' not in response.headers

def test_analyzer_timeout_cleans_temp_file(monkeypatch):
    paths = []
    monkeypatch.setattr('app.main._binary', lambda: 'analyzer')
    def timeout(args, **kwargs):
        paths.append(args[1])
        raise subprocess.TimeoutExpired(args, 180)
    monkeypatch.setattr(subprocess, 'run', timeout)
    response = client.post('/api/analyses', files={'file': ('slow.pcap', PCAP)})
    assert response.status_code == 408 and 'too long' in response.json()['detail']
    assert len(paths) == 1 and not Path(paths[0]).exists()

def test_not_found():
    assert client.get('/api/analyses/missing').status_code == 404

def test_pagination_and_filtering():
    ANALYSES['test'] = {'packets': [
        {'number': 1, 'src_ip': '10.0.0.1', 'dst_ip': '8.8.8.8', 'src_port': 123, 'dst_port': 53, 'transport': 'UDP', 'application': 'DNS'},
        {'number': 2, 'src_ip': '10.0.0.2', 'dst_ip': '1.1.1.1', 'src_port': 5, 'dst_port': 443, 'transport': 'TCP', 'application': 'TLS'},
        {'number': 3, 'src_ip': '10.0.0.3', 'dst_ip': '1.1.1.1', 'src_port': 5, 'dst_port': 80, 'transport': 'TCP', 'application': 'HTTP'},
        {'number': 4, 'src_ip': '10.0.0.4', 'dst_ip': '1.1.1.1', 'src_port': 5, 'dst_port': 443, 'transport': 'TCP', 'application': 'HTTPS'},
    ]}
    assert client.get('/api/analyses/test/packets?page_size=1').json()['items'][0]['number'] == 1
    result = client.get('/api/analyses/test/packets?protocol=TLS&src_ip=10.0.0.2&dst_ip=1.1.1.1&search=10.0.0.2').json()
    assert result['total'] == 1 and result['items'][0]['number'] == 2
    http = client.get('/api/analyses/test/packets?protocol=HTTP').json()
    https = client.get('/api/analyses/test/packets?protocol=HTTPS').json()
    assert [p['number'] for p in http['items']] == [3]
    assert [p['number'] for p in https['items']] == [4]
    assert client.get('/api/analyses/test/packets?sort_by=src_ip&order=desc').json()['items'][0]['number'] == 4
    del ANALYSES['test']

def test_real_cpp_upload_end_to_end():
    binary = os.getenv('DPI_ANALYZER')
    if not binary or not Path(binary).is_file():
        pytest.skip('Set DPI_ANALYZER to the compiled web analyzer to run integration coverage.')
    capture_path = Path(__file__).resolve().parents[2] / 'test_dpi.pcap'
    before = set(Path(tempfile.gettempdir()).glob('dpi-upload-*.pcap'))
    with capture_path.open('rb') as capture:
        response = client.post('/api/analyses', files={'file': ('test_dpi.pcap', capture)})
    assert response.status_code == 201, response.text
    analysis_id = response.json()['analysis_id']
    assert client.get(f'/analysis/{analysis_id}').status_code == 200
    result = client.get(f'/api/analyses/{analysis_id}')
    assert result.status_code == 200
    data = result.json()
    assert data['summary']['total_packets'] == 77
    assert data['summary']['total_bytes'] > 0
    assert data['charts']['protocols']
    assert data['charts']['timeline']
    assert data['flows']
    packets = client.get(f'/api/analyses/{analysis_id}/packets?page=1&page_size=10')
    assert packets.json()['total'] == 77 and len(packets.json()['items']) == 10
    assert client.get(f'/api/analyses/{analysis_id}/packets?search=192.168.1.100').json()['total'] > 0
    assert client.get(f'/api/analyses/{analysis_id}/packets?protocol=TCP').json()['total'] > 0
    assert client.get(f'/api/analyses/{analysis_id}/packets?src_ip=192.168.1.100&dst_ip=142.250.185.206').json()['total'] > 0
    assert client.get(f'/api/analyses/{analysis_id}/packets?sort_by=timestamp&order=desc').json()['items'][0]['timestamp'] >= packets.json()['items'][0]['timestamp']
    assert set(Path(tempfile.gettempdir()).glob('dpi-upload-*.pcap')) == before

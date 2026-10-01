#!/usr/bin/env python3
"""Linux recording API regression checks with synthetic dumpcap output."""

import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

FAKE_DUMPCAP = r'''#!/usr/bin/env python3
import os, pathlib, signal, struct, sys, time
if '-D' in sys.argv:
    sys.exit(0)
path = sys.argv[sys.argv.index('-w') + 1]
iface = sys.argv[sys.argv.index('-i') + 1]
root = pathlib.Path(os.environ['SOCKETTRAIL_SMOKE_CONTROL'])
def block(ty, body):
    body += b'\0' * (-len(body) % 4)
    size = 12 + len(body)
    return struct.pack('<II', ty, size) + body + struct.pack('<I', size)
header = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
header += block(1, struct.pack('<HHI', 101, 0, 0))
frame = bytearray(28)
frame[0] = 0x45
frame[2:4] = struct.pack('>H', 28)
frame[9] = 17
frame[12:16] = bytes([192, 0, 2, 10])
frame[16:20] = bytes([198, 51, 100, 20])
frame[20:28] = struct.pack('>HHHH', 40000, 443, 8, 0)
data = header + block(6, struct.pack('<IIIII', 0, 0, 0, len(frame), len(frame)) + frame)
if iface == 'invalid':
    print('demo interface does not exist', file=sys.stderr)
    sys.exit(1)
if path == '-':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.flush()
    while not (root / 'live-exit').exists():
        time.sleep(.01)
    sys.exit(1)
if iface == 'dump-failure':
    print('demo recording failed', file=sys.stderr)
    sys.exit(1)
p = pathlib.Path(path)
def stop(*_):
    pathlib.Path(path + '.stopping').touch()
    while not pathlib.Path(path + '.release').exists():
        time.sleep(.01)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
p.write_bytes(data)
pathlib.Path(path + '.pid').write_text(str(os.getpid()))
while not pathlib.Path(path + '.exit').exists():
    time.sleep(.01)
sys.exit(1)
'''


def wait_until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.02)
    raise AssertionError('Timed out waiting for the recording state')


class App:
    def __init__(self, binary, root, iface='demo'):
        self.root = root
        root.mkdir()
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        fake = bin_dir / 'dumpcap'
        fake.write_text(FAKE_DUMPCAP)
        fake.chmod(0o755)
        env = os.environ.copy()
        env.update(HOME=str(root), XDG_CACHE_HOME=str(root / 'cache'),
                   XDG_CONFIG_HOME=str(root / 'config'),
                   SOCKETTRAIL_SMOKE_CONTROL=str(root), PATH=str(bin_dir) + ':' + env['PATH'])
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.url = f'http://127.0.0.1:{port}'
        self.process = subprocess.Popen([str(binary), '--no-open', '--port', str(port), '--iface', iface],
                                        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_until(self.ready)
        except BaseException:
            self.close()
            raise

    def ready(self):
        if self.process.poll() is not None:
            raise AssertionError('SocketTrail exited before starting its API')
        try:
            return self.request('/api/ping')
        except (OSError, TimeoutError):
            return False

    def request(self, path, body=None):
        req = urllib.request.Request(self.url + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=8) as response:
            return json.load(response)

    def start(self, filtered=False):
        return self.request('/api/dump/start', {'filtered': filtered})

    def stop(self, path):
        Path(str(path) + '.release').touch()
        return self.request('/api/dump/stop', {})

    def close(self):
        for path in (self.root / 'SocketTrail').glob('*.pcapng'):
            Path(str(path) + '.release').touch()
        self.process.terminate()
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def recording_checks(app):
    first = app.start()
    assert first['ok'], first
    original = app.request('/api/state')['dump']
    assert not app.start()['ok']
    unchanged = app.request('/api/state')['dump']
    assert (unchanged['path'], unchanged['started']) == (original['path'], original['started'])
    path = Path(first['path'])
    with concurrent.futures.ThreadPoolExecutor() as pool:
        stopping = pool.submit(app.request, '/api/dump/stop', {})
        wait_until(lambda: Path(str(path) + '.stopping').exists())
        assert app.request('/api/state')['dump']['busy']
        assert not app.start()['ok']
        assert not app.request('/api/dump/stop', {})['ok']
        Path(str(path) + '.release').touch()
        stopped = stopping.result()
        assert stopped['ok'], stopped
        assert stopped['size'] > 0
    second = app.start()
    assert second['ok'] and second['path'] != first['path']
    assert app.request('/api/state')['dump']['running']
    assert app.stop(second['path'])['ok']
    print('ok: repeat start, stop/start race, repeat stop, clean stop, unique paths')

    app.request('/api/select', {'pid': app.process.pid})
    filtered = app.start(True)
    assert filtered['ok'] and filtered['only']
    path = Path(filtered['path'])
    data = path.read_bytes()
    Path(str(path) + '.part').mkdir()
    result = app.stop(path)
    assert not result['ok'] and result['unfiltered'] and result['error']
    assert path.read_bytes() == data
    info = json.loads(Path(result['sidecar']).read_text())
    assert not info['only_process'] and info['requested_only_process']
    assert not info['processing']['ok']
    print('ok: filter failure preserves capture and reports unfiltered scope')

    exited = app.start()
    assert exited['ok']
    Path(exited['path'] + '.exit').touch()
    outcome = wait_until(lambda: app.request('/api/state')['dump']['result'])
    assert not outcome['ok'] and outcome['error']
    assert not app.request('/api/state')['dump']['running']
    print('ok: recording child exit is finalized as failure')

    (app.root / 'live-exit').touch()
    wait_until(lambda: not app.request('/api/state')['stats']['capture'])
    assert app.request('/api/state')['stats']['capture_hint']
    assert not app.start()['ok']
    print('ok: live capture exit updates status and prevents recording')


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/release/sockettrail').resolve()
    with tempfile.TemporaryDirectory(prefix='sockettrail-recording-smoke-') as tmp:
        root = Path(tmp)
        for iface in ['demo', 'invalid', 'dump-failure']:
            app = App(binary, root / iface, iface)
            try:
                if iface == 'demo':
                    recording_checks(app)
                elif iface == 'invalid':
                    assert not app.request('/api/state')['stats']['capture']
                    assert not app.start()['ok']
                    print('ok: invalid interface is not active capture')
                else:
                    assert app.request('/api/state')['stats']['capture']
                    assert not app.start()['ok']
                    dump = app.request('/api/state')['dump']
                    assert not dump['running'] and not dump['busy']
                    print('ok: failed recording startup does not leave an active operation')
            finally:
                app.close()
    print('recording smoke ok')


if __name__ == '__main__':
    main()

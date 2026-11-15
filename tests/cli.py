#!/usr/bin/env python3
"""CLI regression tests; generated test wallets exist only in a temporary directory."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/vag')
parser.add_argument('--gpu', action='store_true')
args = parser.parse_args()
binary = str(Path(args.binary).resolve())

def run(options, directory, success=True):
    result = subprocess.run([binary, *options], cwd=directory, capture_output=True, text=True, timeout=30)
    assert (result.returncode == 0) == success, f'Unexpected exit status: {options}, {result.returncode}'
    return result

for chain, pattern in [('eth', '^0x'), ('trx', '^T'), ('btc', '^1'), ('btc-p2sh', '^3'), ('btc-bech32', '^bc1q'), ('sol', '.')]:
    with tempfile.TemporaryDirectory() as directory:
        run(['--mode', 'private-key', '-t', '1', '-c', chain, '-r', pattern], directory)
        files = list(Path(directory).glob('*.json'))
        assert len(files) == 1
        wallet = json.loads(files[0].read_text())
        assert re.search(pattern, wallet['address'])
        assert wallet['mnemonic'] == '' and wallet['private_key']
        assert wallet['chain_type'] == chain
        if chain != 'sol':
            assert re.fullmatch('[0-9a-f]{64}', wallet['private_key'])

with tempfile.TemporaryDirectory() as directory:
    for invalid in [[], ['-r', '('], ['-t', '0', '-r', '.'], ['-b', '--benchmark-seconds', '0'], ['--mode', 'unknown', '-r', '.'], ['--gpu', '-r', '.']]:
        run(invalid, directory, success=False)
    result = run(['--mode', 'private-key', '-t', '1', '-b', '--benchmark-seconds', '1', '-r', '.'], directory)
    assert 'Benchmark:' in result.stdout
    assert not list(Path(directory).glob('*.json')), 'Benchmark must not save wallets'

if args.gpu:
    for chain, pattern, extra in [('eth', '^0x00', []), ('eth', '^0xA.*b$', ['--case']), ('eth', '^0x[0-9]', []), ('trx', '^T', [])]:
        with tempfile.TemporaryDirectory() as directory:
            run(['--gpu', '--mode', 'private-key', '--gpu-lanes', '129', '-c', chain, '-r', pattern, *extra], directory)
            files = list(Path(directory).glob('*.json'))
            assert len(files) == 1
            wallet = json.loads(files[0].read_text())
            assert re.search(pattern, wallet['address'])
            assert wallet['mnemonic'] == ''
    with tempfile.TemporaryDirectory() as directory:
        result = run(['--gpu', '--mode', 'private-key', '--gpu-lanes', '129', '-b', '--benchmark-seconds', '1', '-r', '^0x'], directory)
        measured = re.search(r'Benchmark: (\d+) addresses in ([\d.]+)s = ([\d.]+) addresses/s', result.stdout)
        matched = re.search(r'Matching candidates: (\d+)', result.stdout)
        kernel = re.search(r'CUDA kernel time: ([\d.]+)s', result.stdout)
        assert measured and matched and kernel
        count, elapsed, rate = map(float, measured.groups())
        assert int(matched.group(1)) == int(count), 'Unfiltered GPU count must equal returned matches'
        assert abs(rate * elapsed - count) <= count * 0.002
        assert 0 < float(kernel.group(1)) <= elapsed + 0.01
        assert not list(Path(directory).glob('*.json'))
        process = subprocess.Popen([binary, '--gpu', '--mode', 'private-key', '--gpu-lanes', '129', '--looping', '-r', '^0x00'], cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wallets = []
        try:
            deadline = time.monotonic() + 15
            while len(wallets) < 3 and time.monotonic() < deadline:
                assert process.poll() is None, 'Looping mode exited prematurely'
                wallets = []
                for path in Path(directory).glob('*.json'):
                    try:
                        wallets.append(json.loads(path.read_text()))
                    except json.JSONDecodeError:
                        pass  # A writer may still be completing the newest file.
                time.sleep(0.05)
        finally:
            process.terminate()
            process.wait(timeout=10)
        assert len(wallets) >= 3, 'Looping mode failed to produce multiple wallets'
        assert len({wallet['private_key'] for wallet in wallets}) == len(wallets)

print('CLI tests passed' + (' (CPU + CUDA)' if args.gpu else ' (CPU)'))

"""Exercise documented configuration semantics using synthetic placeholders only."""
import json
import pathlib
import subprocess
import tempfile

root = pathlib.Path.cwd()
binary = str(root / '.github/bin/gitleaks')
original = (root / '.gitleaks.toml').read_text()
singular = original.replace('[[allowlist]]', '[allowlist]')
fixed = singular.split('# 路径排除：')[0].replace("  '''^vendor/''',", "  '''^vendor/''',\n  '''^tests/fixtures/''',")
marker = 'custom_key_' + 'A' * 32
results = []

def run_case(name, config, files, expected_count, expected_exit):
    with tempfile.TemporaryDirectory() as directory:
        work = pathlib.Path(directory)
        (work / '.gitleaks.toml').write_text(config)
        for filename, content in files.items():
            target = work / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        run = subprocess.run([binary, 'dir', '.', '--config', '.gitleaks.toml',
                              '--no-banner', '--redact=100', '--report-format', 'sarif',
                              '--report-path', 'result.sarif'], cwd=work, capture_output=True, text=True)
        report = work / 'result.sarif'
        findings = json.loads(report.read_text())['runs'][0].get('results', []) if report.exists() else None
        count = len(findings) if findings is not None else None
        result = {'case': name, 'exit_code': run.returncode, 'findings': count,
                  'report_exists': report.exists(), 'expected_findings': expected_count,
                  'expected_exit': expected_exit,
                  'passed': count == expected_count and run.returncode == expected_exit,
                  'stderr': run.stderr}
        results.append(result)
        print(json.dumps({k: v for k, v in result.items() if k != 'stderr'}))

files = {'normal.txt': marker, 'vendor/example.txt': marker, 'tests/fixtures/example.txt': marker}
run_case('documented-double-bracket-allowlist', original, files, None, 1)
run_case('singular-allowlist-unknown-paths-table', singular, files, 2, 1)
run_case('corrected-allowlist-paths', fixed, files, 1, 1)
run_case('clean-directory', fixed, {'clean.txt': 'hello world'}, 0, 0)
run_case('allow-comment-same-line', fixed, {'sample.txt': marker + ' # gitleaks:allow'}, 0, 0)
run_case('allow-comment-previous-line', fixed, {'sample.txt': '# gitleaks:allow\n' + marker}, 0, 0)
run_case('pragma-comment-same-line', fixed, {'sample.txt': marker + ' # pragma: allowlist secret'}, 1, 1)
(root / 'gitleaks-docs-cases.json').write_text(json.dumps(results, ensure_ascii=False, indent=2))
if not all(item['passed'] for item in results):
    raise SystemExit('Unexpected Gitleaks behavior; inspect gitleaks-docs-cases.json')

# Usage Guide

## Programmatic Library Usage

PyAttackMap is designed for seamless integration into Python applications.

### 1. Basic Directory Scanning

```python
import pyattackmap as pam

result = pam.scan("./src")
print(result.summary())

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.rule_id}: {finding.title}")
    print(f"  Location: {finding.file}:{finding.line}:{finding.col}")
    print(f"  Evidence: {finding.evidence}")
```

### 2. Single File Scanning

```python
import pyattackmap as pam

result = pam.scan_file("backend/app.py")
print(f"Found {len(result)} security issues.")
```

### 3. Scanning In-Memory Code Strings

```python
import pyattackmap as pam

snippet = """
import os
def run():
    target = input()
    os.system('ping ' + target)
"""

result = pam.scan_code(snippet)
for f in result.findings:
    print(f.rule_id, f.title, f.severity)
```

### 4. Custom Configuration & Filtering

```python
import pyattackmap as pam

config = pam.ScanConfig(
    min_severity=pam.Severity.HIGH,
    exclude=[".git", "tests/fixtures"],
    disabled_rules=["PAM003"],
)

analyzer = pam.Analyzer(config=config)
result = analyzer.scan("./src")

# Filter findings programmatically
critical_findings = result.filter(severity=pam.Severity.CRITICAL)
```

### 5. Inspecting Reconstructed Data-Flow Graphs

```python
import pyattackmap as pam

result = pam.scan_file("app.py")
for finding in result.findings:
    if finding.dataflow is not None:
        print(f"Taint propagation trace for {finding.id}:")
        for node in finding.dataflow.nodes:
            print(f"  [{node.kind.value}] {node.label} (line {node.line})")
        # Mermaid diagram syntax
        print(finding.dataflow.to_mermaid())
```

### 6. Exporting JSON Reports

```python
import pyattackmap as pam

result = pam.scan("./my_project")
# Export directly to file
result.to_json("security-report.json")

# Or obtain dictionary
data = result.to_dict()
print("Scan statistics:", data["statistics"])
```

---

## Command-Line Interface (CLI)

```bash
# Scan a directory
pyattackmap scan ./src

# Scan with minimum severity filter
pyattackmap scan ./src --severity HIGH

# Output report in JSON format
pyattackmap scan ./src --format json -o report.json

# List registered security rules
pyattackmap rules

# Check version
pyattackmap --version
```


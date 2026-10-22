# Security Rules Documentation

PyAttackMap includes three core static analysis security rules targeting prevalent vulnerability classes.

---

## PAM001: SQL Injection via Dynamic Query Construction

- **CWE**: [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- **Severity**: `HIGH`
- **Default Confidence**: `HIGH` (when taint flow is verified) / `MEDIUM` (when dynamic string construction reaches sink)
- **Target APIs**: `cursor.execute()`, `connection.execute()`, `session.execute()`, `engine.execute()`, `db.execute()`.

### Detection Patterns
1. Inline f-strings passed as query statements (e.g. `cursor.execute(f"SELECT * FROM users WHERE id = {uid}")`).
2. String concatenation operators (`+`, `%`) passed to SQL execution methods.
3. String formatting methods (`str.format()`) evaluated before execution.
4. Function-local variables constructed dynamically and passed to `execute()`.
5. Tainted input variables originating from `input()`, `request.args`, `os.environ`, etc.

### Safe Counterparts
- Parameterized queries using DB-API place-holders (e.g., `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` or `cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))`).

### Remediation
Always use database driver parameterization. Do not interpolate user variables directly into the query string.

---

## PAM002: Command Injection via Unsafe Shell Execution

- **CWE**: [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- **Severity**: `CRITICAL` (when tainted input reaches shell) / `HIGH` (dynamic shell strings) / `LOW` (static `os.system` invocation)
- **Default Confidence**: `HIGH` (when taint trace exists) / `MEDIUM`
- **Target APIs**: `os.system()`, `os.popen()`, `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_call()`.

### Detection Patterns
1. Calls to `os.system()` or `os.popen()` with dynamically constructed command strings or tainted variables.
2. Invocations of `subprocess` functions where `shell=True` is explicitly specified with formatted strings or variables.
3. Untrusted inputs flowing into command sinks without sanitization.

### Safe Counterparts
- Passing command and arguments as a sequence of strings: `subprocess.run(["ping", "-c", "1", host], shell=False)`.
- Explicit argument sanitization via `shlex.quote()`.

### Remediation
Avoid `os.system()` and `shell=True`. Pass arguments directly as a list to `subprocess.run()` with `shell=False`.

---

## PAM003: Unsafe Deserialization via pickle

- **CWE**: [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- **Severity**: `CRITICAL` (when untrusted tainted input reaches pickle) / `HIGH`
- **Default Confidence**: `HIGH` (when taint flow verified) / `MEDIUM`
- **Target APIs**: `pickle.load()`, `pickle.loads()`, `_pickle.load()`, `_pickle.loads()`, `cPickle.load()`, `cPickle.loads()`.

### Detection Patterns
1. Deserialization calls receiving data originating from external sources (`input()`, network request attributes, environment variables).
2. Direct calls to `pickle.load()` on unverified streams or files.

### Safe Counterparts
- Standard structured formats: `json.loads()`, `json.load()`.
- Safe parsers: Protocol Buffers, FlatBuffers, or cryptographic signature verification (HMAC).

### Remediation
Never use `pickle` to deserialize untrusted data. Use `json` or schema-validated formats.


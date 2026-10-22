# Data-Flow and Taint Tracking

PyAttackMap implements a scoped intra-procedural taint-tracking engine designed to produce explainable data-flow graphs for security findings.

## Scope and Principles

1. **Intra-Procedural Scope**: Analysis occurs within distinct lexical boundaries:
   - Module top-level body.
   - Synchronous and asynchronous function bodies (`def`, `async def`).
   - Class methods.
2. **Def-Use Tracking**: The engine tracks the lifecycle of tainted variables from their initial definition to their arrival at a sensitive sink.
3. **No Phantom Traces**: Nodes and edges are instantiated only when concrete AST operations demonstrate data movement.

## Components

### 1. Taint Sources
Expressions that introduce untrusted external input:
- Built-in `input()` calls.
- Environment variables: `os.environ`, `os.environ.get()`, `os.getenv()`.
- Command-line arguments: `sys.argv[...]`.
- Web request attributes: `request.args`, `request.form`, `request.values`, `request.data`, `request.json`, `request.GET`, `request.POST`.

### 2. Propagation
Data movement operations tracked by the engine:
- Direct variable assignment: `b = a`.
- Augmented assignments: `b += a`.
- String concatenations: `cmd = "ping " + host`.
- Formatted string literals (f-strings): `f"SELECT * FROM u WHERE id = {uid}"`.
- Format method calls: `"echo {}".format(target)`.

### 3. Sanitizers
Expressions that neutralize taint:
- Shell quoting: `shlex.quote(var)`.
- Numeric type casts: `int(var)`, `float(var)`, `bool(var)`.
- SQL parameter escaping: `sql.Literal(var)`.

### 4. Sinks
Sensitive operations whose parameters are monitored:
- SQL query execution (`execute`, `executemany`).
- OS command execution (`os.system`, `subprocess.run`).
- Deserialization routines (`pickle.loads`, `pickle.load`).

## Graph Output

When a taint trace connects a source to a sink, a `DataFlowGraph` is attached to the `Finding`:
- **Nodes**: Contain node kind (`SOURCE`, `PROPAGATION`, `SANITIZER`, `SINK`), source coordinates (file, line, col), human-readable label, and code snippet.
- **Edges**: Directed relationships (`source_id` -> `target_id`) with transition descriptions.
- **Export**: Can be rendered directly as a Mermaid flowchart diagram via `dataflow.to_mermaid()`.


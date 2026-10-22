# Static Analysis Limitations

Every static analysis tool operates with defined theoretical and practical boundaries. PyAttackMap explicitly identifies its boundaries:

## 1. Intra-Procedural vs. Inter-Procedural Analysis
- **Current Behavior**: PyAttackMap tracks taint within function and method bodies (intra-procedural).
- **Limitation**: Taint passed across complex function call boundaries (e.g. `clean_val = helper_func(user_input)`) or inter-module imports is not resolved across files. Global variable mutations are not tracked across thread or module boundaries.

## 2. Dynamic Python Features
- **Dynamic Attribute Access**: Taint flowing through `getattr()`, `setattr()`, or `__dict__` manipulation is not modeled.
- **Dynamic Imports**: Modules imported via `__import__()` or `importlib.import_module()` are not statically evaluated.
- **`eval` and `exec`**: PyAttackMap does not execute or emulate Python code. Dynamic metaclass manipulations cannot be fully reasoned about at compile time.

## 3. Heuristic Sanitization
- PyAttackMap recognizes explicit sanitizer functions (`shlex.quote`, `int`, `float`, and configured sanitizers). Custom or project-specific validation logic (e.g., regex checks or allowlists) must be declared in `ScanConfig(sanitizers=[...])` to prevent false alarms.

## 4. Complex Database Abstractions
- PyAttackMap inspects standard DB-API cursor and connection patterns. Complex custom ORM abstraction layers that wrap raw queries inside non-standard methods may require custom sink definitions.


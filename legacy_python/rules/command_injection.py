"""PAM002: Command Injection Detection Rule."""

from __future__ import annotations

import ast

from pyattackmap.config import ScanConfig
from pyattackmap.dataflow.engine import IntraProceduralTaintTracker, TaintTrace
from pyattackmap.dataflow.sanitizers import SanitizerDetector
from pyattackmap.dataflow.sinks import SinkDetector
from pyattackmap.models import Confidence, Finding, Severity
from pyattackmap.parser import ParsedSource
from pyattackmap.rules.base import Rule
from pyattackmap.rules.sql_injection import is_dynamic_string_construction


class CommandInjectionRule(Rule):
    """Detects unsafe shell command execution patterns and unescaped argument construction."""

    rule_id = "PAM002"
    title = "Potential Command Injection via Unsafe Shell Execution"
    description = (
        "Invoking system commands through a shell with dynamically constructed strings "
        "can allow execution of arbitrary host commands."
    )
    severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    cwe = "CWE-78"

    REMEDIATION = (
        "Pass arguments as a sequence (list of strings) and avoid using 'shell=True' or 'os.system()'.\n"
        "Example (Safe Sequence Execution):\n"
        "    # Safe: arguments are passed directly without shell expansion:\n"
        "    subprocess.run(['ping', '-c', '1', host], shell=False, check=True)"
    )

    def run(self, parsed: ParsedSource, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        sink_detector = SinkDetector(config.sinks)
        sanitizer_detector = SanitizerDetector(config.sanitizers)

        # Track variables that were assigned from explicit sanitizer calls
        sanitized_vars: set[str] = set()
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Call):
                    is_san, _ = sanitizer_detector.is_sanitizer_call(node.value)
                    if is_san:
                        sanitized_vars.add(node.targets[0].id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                if isinstance(node.value, ast.Call):
                    is_san, _ = sanitizer_detector.is_sanitizer_call(node.value)
                    if is_san:
                        sanitized_vars.add(node.target.id)

        # 1. Taint analysis to find verified data-flow paths to command sinks
        taint_tracker = IntraProceduralTaintTracker(parsed, config)
        taint_traces = taint_tracker.analyze()

        taint_by_call: dict[int, TaintTrace] = {}
        for trace in taint_traces:
            is_cmd, _ = sink_detector.is_command_sink(trace.sink_call)
            if is_cmd:
                taint_by_call[id(trace.sink_call)] = trace

        # Track dynamically assigned variables (excluding those exclusively using sanitized variables)
        assigned_dynamic: dict[str, tuple[str, int]] = {}
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                is_dyn, dyn_kind = is_dynamic_string_construction(node.value)
                if is_dyn:
                    referenced = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                    if not (referenced and referenced.issubset(sanitized_vars)):
                        assigned_dynamic[node.targets[0].id] = (dyn_kind, node.lineno)

        # 2. Inspect command sinks in AST
        for node in ast.walk(parsed.tree):
            if not isinstance(node, ast.Call):
                continue

            is_cmd, call_name = sink_detector.is_command_sink(node)
            if not is_cmd or not node.args:
                continue

            cmd_arg = node.args[0]
            lineno = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0)
            end_lineno = getattr(node, "end_lineno", lineno)
            end_col = getattr(node, "end_col_offset", col)
            snippet = parsed.get_snippet(lineno, end_lineno)

            # If it's a subprocess call, check whether shell is enabled
            is_subprocess = "subprocess" in call_name
            shell_arg_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                    shell_arg_true = True

            # If it is a subprocess call without shell=True, and argument is a list or tuple: SAFE!
            if is_subprocess and not shell_arg_true and isinstance(cmd_arg, (ast.List, ast.Tuple)):
                continue

            # Check for verified taint trace
            trace = taint_by_call.get(id(node))
            if trace:
                finding_id = f"PAM002-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"Call to '{call_name}' executes system command receiving tainted input from "
                            f"{trace.source_node.label} at line {trace.source_node.line}."
                        ),
                        severity=Severity.CRITICAL if ("os.system" in call_name or shell_arg_true) else self.severity,
                        confidence=Confidence.HIGH,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Tainted data reaches command execution in '{call_name}()'.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=trace.graph if config.show_dataflow else None,
                        metadata={"sink": call_name, "shell_true": shell_arg_true},
                    )
                )
                continue

            # Subprocess with shell=True and dynamic string or variable
            if is_subprocess and shell_arg_true:
                is_dyn, dyn_kind = is_dynamic_string_construction(cmd_arg)
                referenced = {n.id for n in ast.walk(cmd_arg) if isinstance(n, ast.Name)}
                if is_dyn and referenced and referenced.issubset(sanitized_vars):
                    continue

                pattern_desc = dyn_kind if is_dyn else "shell=True invocation"
                finding_id = f"PAM002-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Subprocess call '{call_name}' uses 'shell=True' with {pattern_desc}.",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Subprocess invoked with shell=True ({pattern_desc}).",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=None,
                        metadata={"sink": call_name, "shell_true": True, "pattern": pattern_desc},
                    )
                )
                continue

            # os.system or os.popen with dynamic string construction or variable
            if "os.system" in call_name or "os.popen" in call_name or call_name in {"system", "popen"}:
                is_dyn, dyn_kind = is_dynamic_string_construction(cmd_arg)
                referenced = {n.id for n in ast.walk(cmd_arg) if isinstance(n, ast.Name)}
                if is_dyn and referenced and referenced.issubset(sanitized_vars):
                    # Explicitly sanitized inputs are safe
                    continue

                if is_dyn:
                    finding_id = f"PAM002-{parsed.file_path}-{lineno}-{col}"
                    findings.append(
                        Finding(
                            id=finding_id,
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Call to '{call_name}' passes command constructed via {dyn_kind}.",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file=parsed.file_path,
                            line=lineno,
                            end_line=end_lineno,
                            col=col,
                            end_col=end_col,
                            snippet=snippet,
                            evidence=f"Command string constructed dynamically using {dyn_kind}.",
                            remediation=self.REMEDIATION,
                            cwe=self.cwe,
                            dataflow=None,
                            metadata={"sink": call_name, "pattern": dyn_kind},
                        )
                    )
                elif isinstance(cmd_arg, ast.Name) and cmd_arg.id in assigned_dynamic:
                    dyn_kind, assign_line = assigned_dynamic[cmd_arg.id]
                    finding_id = f"PAM002-{parsed.file_path}-{lineno}-{col}"
                    findings.append(
                        Finding(
                            id=finding_id,
                            rule_id=self.rule_id,
                            title=self.title,
                            description=(
                                f"Call to '{call_name}' passes variable '{cmd_arg.id}' "
                                f"built via {dyn_kind} at line {assign_line}."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file=parsed.file_path,
                            line=lineno,
                            end_line=end_lineno,
                            col=col,
                            end_col=end_col,
                            snippet=snippet,
                            evidence=f"Command variable '{cmd_arg.id}' built via {dyn_kind}.",
                            remediation=self.REMEDIATION,
                            cwe=self.cwe,
                            dataflow=None,
                            metadata={"sink": call_name, "variable": cmd_arg.id, "pattern": dyn_kind},
                        )
                    )
                else:
                    # Static literal or unassigned variable passed to shell API
                    finding_id = f"PAM002-{parsed.file_path}-{lineno}-{col}"
                    findings.append(
                        Finding(
                            id=finding_id,
                            rule_id=self.rule_id,
                            title="Use of Risky Shell Execution API (os.system)",
                            description=f"Call to '{call_name}' executes a command via system shell. Prefer subprocess.run() with an argument list.",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            file=parsed.file_path,
                            line=lineno,
                            end_line=end_lineno,
                            col=col,
                            end_col=end_col,
                            snippet=snippet,
                            evidence=f"Command executed via shell-enabled '{call_name}()'.",
                            remediation=self.REMEDIATION,
                            cwe=self.cwe,
                            dataflow=None,
                            metadata={"sink": call_name, "pattern": "shell_call"},
                        )
                    )

        return findings

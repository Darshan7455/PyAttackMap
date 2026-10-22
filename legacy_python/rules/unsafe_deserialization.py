"""PAM003: Unsafe Deserialization Detection Rule."""

from __future__ import annotations

import ast

from pyattackmap.config import ScanConfig
from pyattackmap.dataflow.engine import IntraProceduralTaintTracker, TaintTrace
from pyattackmap.dataflow.sinks import SinkDetector
from pyattackmap.models import Confidence, Finding, Severity
from pyattackmap.parser import ParsedSource
from pyattackmap.rules.base import Rule


class UnsafeDeserializationRule(Rule):
    """Detects unsafe object deserialization via pickle and related insecure serializers."""

    rule_id = "PAM003"
    title = "Potential Unsafe Deserialization via pickle"
    description = (
        "Deserializing untrusted data with pickle allows arbitrary Python object construction "
        "and remote code execution via __reduce__ methods."
    )
    severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM
    cwe = "CWE-502"

    REMEDIATION = (
        "Avoid using pickle for untrusted or external input. Use safe data interchange "
        "formats such as JSON, Protocol Buffers, or HMAC-signed serializers.\n"
        "Example (Safe Serialization):\n"
        "    import json\n"
        "    # Safe structured data deserialization:\n"
        "    data = json.loads(payload)"
    )

    def run(self, parsed: ParsedSource, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        sink_detector = SinkDetector(config.sinks)

        # 1. Taint analysis to check if deserialized data originates from an untrusted source
        taint_tracker = IntraProceduralTaintTracker(parsed, config)
        taint_traces = taint_tracker.analyze()

        taint_by_call: dict[int, TaintTrace] = {}
        for trace in taint_traces:
            is_deser, _ = sink_detector.is_deserialization_sink(trace.sink_call)
            if is_deser:
                taint_by_call[id(trace.sink_call)] = trace

        # 2. Inspect deserialization calls in AST
        for node in ast.walk(parsed.tree):
            if not isinstance(node, ast.Call):
                continue

            is_deser, call_name = sink_detector.is_deserialization_sink(node)
            if not is_deser or not node.args:
                continue

            lineno = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0)
            end_lineno = getattr(node, "end_lineno", lineno)
            end_col = getattr(node, "end_col_offset", col)
            snippet = parsed.get_snippet(lineno, end_lineno)

            # Check if tainted data reaches pickle
            trace = taint_by_call.get(id(node))
            if trace:
                finding_id = f"PAM003-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"Call to '{call_name}' deserializes untrusted data originating from "
                            f"{trace.source_node.label} at line {trace.source_node.line}."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Untrusted tainted payload deserialized by '{call_name}()'.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=trace.graph if config.show_dataflow else None,
                        metadata={"sink": call_name, "taint_verified": True},
                    )
                )
            else:
                # Risky API call without confirmed taint trace
                finding_id = f"PAM003-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Potentially unsafe call to '{call_name}' without verified input isolation.",
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Call to '{call_name}()' may be vulnerable if input is attacker-controlled.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=None,
                        metadata={"sink": call_name, "taint_verified": False},
                    )
                )

        return findings


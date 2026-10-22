"""Example: Inspecting intra-procedural data-flow traces and rendering Mermaid graphs."""

from pathlib import Path
import pyattackmap as pam


def main() -> None:
    sample_file = Path(__file__).parent / "sample_project" / "vulnerable.py"
    result = pam.scan_file(sample_file)

    for finding in result.findings:
        if finding.dataflow is not None and finding.dataflow.nodes:
            print("=" * 60)
            print(f"Data-Flow Path for Finding {finding.id} ({finding.rule_id})")
            print("=" * 60)
            print("Nodes in propagation order:")
            for node in finding.dataflow.nodes:
                print(f"  [{node.kind.value}] Line {node.line}: {node.label}")

            print("\nMermaid Flowchart Syntax:")
            print(finding.dataflow.to_mermaid())
            print()


if __name__ == "__main__":
    main()


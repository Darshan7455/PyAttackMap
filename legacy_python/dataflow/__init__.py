"""Data-flow and taint-tracking engine package for PyAttackMap."""

from pyattackmap.dataflow.engine import IntraProceduralTaintTracker, TaintTrace
from pyattackmap.dataflow.graph import DataFlowGraphBuilder
from pyattackmap.dataflow.sanitizers import SanitizerDetector
from pyattackmap.dataflow.sinks import SinkDetector
from pyattackmap.dataflow.sources import SourceDetector

__all__ = [
    "IntraProceduralTaintTracker",
    "TaintTrace",
    "DataFlowGraphBuilder",
    "SourceDetector",
    "SinkDetector",
    "SanitizerDetector",
]


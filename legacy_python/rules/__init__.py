"""Rules package registering built-in static analysis checks."""

from pyattackmap.rules.base import Rule
from pyattackmap.rules.command_injection import CommandInjectionRule
from pyattackmap.rules.registry import RuleRegistry, default_registry, register_rule
from pyattackmap.rules.sql_injection import SqlInjectionRule
from pyattackmap.rules.unsafe_deserialization import UnsafeDeserializationRule

# Register default rules
default_registry.register(SqlInjectionRule)
default_registry.register(CommandInjectionRule)
default_registry.register(UnsafeDeserializationRule)

__all__ = [
    "Rule",
    "RuleRegistry",
    "default_registry",
    "register_rule",
    "SqlInjectionRule",
    "CommandInjectionRule",
    "UnsafeDeserializationRule",
]


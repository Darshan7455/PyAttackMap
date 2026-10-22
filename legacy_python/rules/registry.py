"""Registry and discovery mechanisms for PyAttackMap rules."""

from __future__ import annotations

from typing import Type

from pyattackmap.config import ScanConfig
from pyattackmap.exceptions import RuleError
from pyattackmap.rules.base import Rule


class RuleRegistry:
    """Registry maintaining active static security rules."""

    def __init__(self) -> None:
        self._rules: dict[str, Type[Rule]] = {}

    def register(self, rule_cls: Type[Rule]) -> Type[Rule]:
        """Register a new Rule class."""
        if not hasattr(rule_cls, "rule_id") or not rule_cls.rule_id:
            raise RuleError(f"Rule class {rule_cls.__name__} must define a non-empty 'rule_id'")
        rule_id = rule_cls.rule_id.strip().upper()
        self._rules[rule_id] = rule_cls
        return rule_cls

    def get(self, rule_id: str) -> Type[Rule] | None:
        return self._rules.get(rule_id.strip().upper())

    def list_rules(self) -> list[Type[Rule]]:
        return list(self._rules.values())

    def get_enabled_instances(self, config: ScanConfig) -> list[Rule]:
        """Return instantiated rules filtered by scan configuration."""
        instances: list[Rule] = []
        for rule_id, rule_cls in self._rules.items():
            if config.is_rule_enabled(rule_id):
                instances.append(rule_cls())
        return instances


# Global default registry
default_registry = RuleRegistry()


def register_rule(rule_cls: Type[Rule]) -> Type[Rule]:
    """Decorator for registering custom rules with the default registry."""
    return default_registry.register(rule_cls)


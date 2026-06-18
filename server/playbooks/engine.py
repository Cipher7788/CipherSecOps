"""Playbook execution engine."""

import logging
import os
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from server.playbooks import actions as action_module

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Map action names in YAML to callable functions in actions.py
_ACTION_MAP: Dict[str, Any] = {
    "isolate_endpoint": action_module.isolate_endpoint,
    "kill_process": action_module.kill_process,
    "alert_soc": action_module.alert_soc,
    "create_incident_ticket": action_module.create_incident_ticket,
    "block_ip": action_module.block_ip,
    "collect_forensics": action_module.collect_forensics,
}


class PlaybookEngine:
    """Loads YAML playbook templates and executes their steps."""

    def load_template(self, name: str) -> Dict[str, Any]:
        """Load a YAML playbook template by name (without .yml extension)."""
        path = _TEMPLATES_DIR / f"{name}.yml"
        if not path.exists():
            raise FileNotFoundError(f"Playbook template not found: {path}")
        with open(path, "r") as fh:
            data = yaml.safe_load(fh)
        logger.debug("Loaded playbook template: %s", name)
        return data

    async def execute(self, playbook_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Load a template by name and execute its steps."""
        template = self.load_template(playbook_name)
        steps: List[Dict[str, Any]] = template.get("steps", [])
        return await self.execute_steps(steps, context)

    async def execute_steps(
        self, steps: List[Dict[str, Any]], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a list of step dicts with optional condition guards."""
        results: List[Dict[str, Any]] = []
        for step in steps:
            step_name: str = step.get("name", "unnamed")
            condition: Optional[str] = step.get("condition")
            action_name: str = step.get("action", "")
            params: Dict[str, Any] = step.get("params", {})

            # Evaluate optional condition
            if condition and not self._evaluate_condition(condition, context):
                logger.debug("Skipping step '%s': condition not met", step_name)
                results.append({"step": step_name, "status": "skipped", "reason": "condition_false"})
                continue

            # Resolve parameter placeholders from context
            resolved_params = self._resolve_params(params, context)

            action_func = _ACTION_MAP.get(action_name)
            if action_func is None:
                logger.warning("Unknown action '%s' in step '%s'", action_name, step_name)
                results.append({"step": step_name, "status": "error", "reason": f"unknown_action:{action_name}"})
                continue

            try:
                result = await action_func(**resolved_params)
                logger.info("Step '%s' executed successfully: %s", step_name, result)
                results.append({"step": step_name, "status": "success", "result": result})
            except Exception as exc:
                logger.error("Step '%s' failed: %s", step_name, exc, exc_info=True)
                results.append({"step": step_name, "status": "error", "reason": str(exc)})

        overall_status = "success" if all(r.get("status") in {"success", "skipped"} for r in results) else "partial"
        return {"status": overall_status, "steps_executed": len(steps), "results": results}

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a simple condition expression against the playbook context.
        Supported syntax: 'key operator value', e.g. 'risk_score >= 60' or 'severity == "critical"'.
        This implementation uses shlex to support quoted values and is conservative: invalid
        or unsupported conditions return False (don't execute the step).
        """
        try:
            # Use shlex to allow quoted values and preserve spacing inside quotes
            parts = shlex.split(condition)
            if len(parts) < 3:
                logger.warning("Invalid condition format: %r", condition)
                return False
            key = parts[0]
            operator = parts[1]
            expected = " ".join(parts[2:])

            actual = context.get(key)
            if actual is None:
                # Missing context key -> condition not met
                logger.debug("Condition key '%s' missing from context", key)
                return False

            # Try numeric comparison if both sides parse as numbers
            try:
                actual_num = float(actual)
                expected_num = float(expected)
                if operator == ">=":
                    return actual_num >= expected_num
                if operator == "<=":
                    return actual_num <= expected_num
                if operator == ">":
                    return actual_num > expected_num
                if operator == "<":
                    return actual_num < expected_num
                if operator == "==":
                    return actual_num == expected_num
                if operator == "!=":
                    return actual_num != expected_num
                logger.warning("Unsupported numeric operator '%s' in condition '%s'", operator, condition)
                return False
            except (ValueError, TypeError):
                # Fall back to string comparison
                actual_str = str(actual)
                # Remove surrounding quotes from expected if present
                if (expected.startswith('"') and expected.endswith('"')) or (
                    expected.startswith("'") and expected.endswith("'")
                ):
                    expected_str = expected[1:-1]
                else:
                    expected_str = expected

                if operator == "==":
                    return actual_str == expected_str
                if operator == "!=":
                    return actual_str != expected_str
                if operator.lower() == "in":
                    return expected_str in actual_str
                if operator.lower() == "notin" or operator.lower() == "not_in":
                    return expected_str not in actual_str

                logger.warning("Unsupported operator '%s' in condition '%s'", operator, condition)
                return False
        except Exception as exc:
            logger.error("Condition evaluation error: %s", exc, exc_info=True)
            return False

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Replace '{{key}}' placeholders in param values with context values.

        Supports:
        - Entire-value placeholders where the resolved value may be a non-string (int/dict/list)
        - Embedded placeholders inside strings and multiple placeholders per value
        """
        resolved: Dict[str, Any] = {}
        placeholder_re = re.compile(r"\{\{\s*([^}]+)\s*\}\}")

        for k, v in params.items():
            if isinstance(v, str):
                # Exact-match placeholder -> return original type if present in context
                m = placeholder_re.fullmatch(v)
                if m:
                    ctx_key = m.group(1).strip()
                    if ctx_key not in context:
                        logger.warning("Playbook param '%s' references missing context key '%s'", k, ctx_key)
                        resolved[k] = v
                    else:
                        resolved[k] = context.get(ctx_key)
                    continue

                # Embedded or multiple placeholders -> replace with stringified context values
                def _repl(match: re.Match) -> str:
                    ctx_key = match.group(1).strip()
                    if ctx_key not in context:
                        logger.warning(
                            "Playbook param '%s' references missing context key '%s'", k, ctx_key
                        )
                        return match.group(0)
                    val = context.get(ctx_key)
                    # Prefer simple string representation for embedding
                    return str(val)

                replaced = placeholder_re.sub(_repl, v)
                resolved[k] = replaced
            else:
                # Non-string params are left as-is
                resolved[k] = v
        return resolved

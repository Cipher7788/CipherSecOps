"""Playbook execution engine."""

import logging
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
                results.append(
                    {"step": step_name, "status": "skipped", "reason": "condition_false"}
                )
                continue

            # Resolve parameter placeholders from context
            resolved_params = self._resolve_params(params, context)

            action_func = _ACTION_MAP.get(action_name)
            if action_func is None:
                logger.warning("Unknown action '%s' in step '%s'", action_name, step_name)
                results.append(
                    {
                        "step": step_name,
                        "status": "error",
                        "reason": f"unknown_action:{action_name}",
                    }
                )
                continue

            try:
                result = await action_func(**resolved_params)
                logger.info("Step '%s' executed successfully: %s", step_name, result)
                results.append({"step": step_name, "status": "success", "result": result})
            except Exception as exc:
                logger.error("Step '%s' failed: %s", step_name, exc, exc_info=True)
                results.append({"step": step_name, "status": "error", "reason": str(exc)})

        overall_status = (
            "success"
            if all(r.get("status") in {"success", "skipped"} for r in results)
            else "partial"
        )
        return {"status": overall_status, "steps_executed": len(steps), "results": results}

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a simple condition expression against the playbook context.
        Supported syntax: 'key operator value', e.g. 'risk_score >= 60' or 'severity == critical'.
        """
        try:
            parts = condition.split()
            if len(parts) != 3:
                logger.warning("Invalid condition format: %r", condition)
                return True  # Default to executing the step
            key, operator, expected = parts
            actual = context.get(key)
            if actual is None:
                return False
            # Try numeric comparison
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
            except ValueError:
                pass
            # String comparison
            if operator == "==":
                return str(actual) == expected
            if operator == "!=":
                return str(actual) != expected
            logger.warning("Unsupported operator '%s' in condition '%s'", operator, condition)
            return True
        except Exception as exc:
            logger.error("Condition evaluation error: %s", exc)
            return True

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Replace '{{key}}' placeholders in param values with context values."""
        resolved: Dict[str, Any] = {}
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("{{") and v.endswith("}}"):
                ctx_key = v[2:-2].strip()
                if ctx_key not in context:
                    logger.warning(
                        "Playbook param '%s' references missing context key '%s'", k, ctx_key
                    )
                resolved[k] = context.get(ctx_key, v)
            else:
                resolved[k] = v
        return resolved

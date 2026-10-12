"""Configuration manager for loading, validating, and caching MCP Sentinel security policies."""

import json
from pathlib import Path
from typing import Optional, Union

import yaml

from mcp_sentinel.core.exceptions import ConfigurationError
from mcp_sentinel.core.models import GlobalPolicy


DEFAULT_CONFIG_PATH = Path("config/default_policy.yaml")


def load_policy(policy_path: Optional[Union[str, Path]] = None) -> GlobalPolicy:
    """Load and validate a GlobalPolicy from a YAML or JSON file.

    Args:
        policy_path: Filepath to policy definition. If None, uses default built-in policy.

    Returns:
        Validated GlobalPolicy instance.

    Raises:
        ConfigurationError: If the file is unreadable, malformed, or fails schema validation.
    """
    if policy_path is None:
        return GlobalPolicy()

    path = Path(policy_path)
    if not path.exists():
        raise ConfigurationError(f"Policy file not found: {path.resolve()}")

    try:
        raw_text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in [".yaml", ".yml"]:
            data = yaml.safe_load(raw_text)
        elif path.suffix.lower() == ".json":
            data = json.loads(raw_text)
        else:
            # Fallback to YAML parser as YAML is a superset of JSON
            data = yaml.safe_load(raw_text)

        if not isinstance(data, dict):
            raise ConfigurationError(f"Policy file {path} did not parse into a top-level dictionary")

        return GlobalPolicy.model_validate(data)
    except Exception as exc:
        if isinstance(exc, ConfigurationError):
            raise
        raise ConfigurationError(f"Failed to parse policy file {path}: {exc}") from exc


def dump_policy_yaml(policy: GlobalPolicy, destination: Path) -> None:
    """Serialize a GlobalPolicy instance to a YAML file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    policy_dict = policy.model_dump(mode="json")
    with open(destination, "w", encoding="utf-8") as f:
        yaml.dump(policy_dict, f, sort_keys=False, indent=2)

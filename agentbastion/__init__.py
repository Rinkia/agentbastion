"""agentbastion - a checkpoint between a business's AI agent and the world.

Three guards, one product:
  1. inbound  - block prompt injection / jailbreaks before they reach the model
  2. tool     - stop the agent doing something dangerous (mass email, delete, exfil)
  3. outbound - stop the agent leaking PII / secrets in its reply

Defense in depth, not a silver bullet. See README.
"""

from .firewall import Firewall, guard, Verdict, BlockedError
from .tools import PolicyError, PolicyV2, ToolPolicy, ToolBlocked, load_policy, load_policy_v2
from .events import Event, EventLog, dashboard

__version__ = "0.12.0"

__all__ = [
    "Firewall",
    "guard",
    "Verdict",
    "BlockedError",
    "ToolPolicy",
    "ToolBlocked",
    "load_policy",
    "load_policy_v2",
    "PolicyV2",
    "PolicyError",
    "Event",
    "EventLog",
    "dashboard",
]

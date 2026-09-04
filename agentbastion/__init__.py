"""agentbastion - a checkpoint between a business's AI agent and the world.

Three guards, one product:
  1. inbound  - block prompt injection / jailbreaks before they reach the model
  2. tool     - stop the agent doing something dangerous (mass email, delete, exfil)
  3. outbound - stop the agent leaking PII / secrets in its reply

Defense in depth, not a silver bullet. See README.
"""

from .firewall import Firewall, guard, Verdict, BlockedError
from .tools import ToolPolicy, ToolBlocked, load_policy
from .events import Event, EventLog, dashboard

__version__ = "0.8.0"

__all__ = [
    "Firewall",
    "guard",
    "Verdict",
    "BlockedError",
    "ToolPolicy",
    "ToolBlocked",
    "load_policy",
    "Event",
    "EventLog",
    "dashboard",
]

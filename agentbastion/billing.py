"""Metered billing: turn the per-tenant usage counters into billable units and
report the delta to a billing provider (Stripe).

Design:
  - `BillingReporter` reads the `UsageMeter` snapshot, computes each tenant's
    billable units (sum of check calls), and reports only the DELTA since the
    last run (state persisted to a JSON file). Idempotent-ish: run it on a cron.
  - The provider is behind a tiny `BillingBackend` protocol so it's testable
    without hitting Stripe. `StripeBackend` is optional (needs the `stripe` SDK)
    and fail-soft - a billing outage must never break the request path.

ponytail: billable unit = one check call. If you later price stages differently
(e.g. judge-backed checks cost more), split the units here, not at the callsite.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional, Protocol

log = logging.getLogger("agentbastion.billing")

# Which usage counters count as billable check calls (blocks are a subset, not billed separately).
BILLABLE_UNITS = ("input", "output", "tool", "tool_result")


class BillingBackend(Protocol):
    def report(self, customer: str, quantity: int) -> None: ...


class NullBackend:
    """Default: no provider configured. Logs what would be billed."""

    def report(self, customer: str, quantity: int) -> None:
        log.info("billing (null): would report %d units for customer %s", quantity, customer)


class StripeBackend:
    """Reports metered usage to Stripe via the Billing Meters API. Fail-soft."""

    def __init__(self, api_key: str, meter_event: str) -> None:
        import stripe

        self._stripe = stripe
        self._stripe.api_key = api_key
        self._meter_event = meter_event

    def report(self, customer: str, quantity: int) -> None:
        try:
            self._stripe.billing.MeterEvent.create(
                event_name=self._meter_event,
                payload={"stripe_customer_id": customer, "value": str(quantity)},
            )
        except Exception as e:  # noqa: BLE001 - billing must never break a request
            log.warning("stripe meter event failed for %s: %s", customer, e)


def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def load_customer_map(path: Optional[str]) -> dict[str, str]:
    """Map tenant name -> Stripe customer id, from a JSON file. Empty if unset."""
    return _load_json(path) if path else {}


class BillingReporter:
    def __init__(self, meter, backend: BillingBackend, customer_map: dict[str, str], state_path: str) -> None:
        self._meter = meter
        self._backend = backend
        self._customers = customer_map
        self._state_path = state_path
        self._state = _load_json(state_path)  # tenant -> last reported billable total

    @staticmethod
    def _billable(counts: dict) -> int:
        return sum(int(counts.get(u, 0)) for u in BILLABLE_UNITS)

    def report(self) -> dict:
        """Report each tenant's new usage since the last run. Returns a summary."""
        out: dict = {}
        for tenant, counts in self._meter.snapshot().items():
            total = self._billable(counts)
            delta = total - int(self._state.get(tenant, 0))
            if delta <= 0:
                continue
            customer = self._customers.get(tenant)
            if not customer:
                out[tenant] = {"reported": 0, "skipped": "no stripe customer mapped", "pending_units": delta}
                continue
            self._backend.report(customer, delta)
            self._state[tenant] = total
            out[tenant] = {"reported": delta, "customer": customer}
        self._save()
        return out

    def _save(self) -> None:
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f)
        os.replace(tmp, self._state_path)


def build_reporter(meter, state_path: str = "billing_state.json") -> BillingReporter:
    """Assemble a reporter from env. StripeBackend if AGENTBASTION_STRIPE_API_KEY
    is set, else NullBackend (still computes + returns deltas)."""
    api_key = os.getenv("AGENTBASTION_STRIPE_API_KEY")
    meter_event = os.getenv("AGENTBASTION_STRIPE_METER", "agentbastion_checks")
    backend: BillingBackend = StripeBackend(api_key, meter_event) if api_key else NullBackend()
    customers = load_customer_map(os.getenv("AGENTBASTION_BILLING_MAP"))
    return BillingReporter(meter, backend, customers, state_path)

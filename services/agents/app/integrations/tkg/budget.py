"""Recon-only admission accounting at the protected model boundary."""

import json
from functools import partial

from app.core.cost_telemetry import model_token_prices


class ModelBudgetStop(RuntimeError):
    pass


class ModelBudget:
    def __init__(self, limits):
        self.limits = limits
        self.tokens = 0
        self.estimated_cost = 0.0
        self.provider_calls = 0

    def guard(self, *, final):
        return partial(self.admit, final=final)

    def admit(self, model, messages, *, final):
        limits = self.limits
        prices = model_token_prices(model)
        if prices is None:
            if limits.unknown_input_usd_per_1k is None or limits.unknown_output_usd_per_1k is None:
                raise ModelBudgetStop("model_price_unavailable")
            prices = limits.unknown_input_usd_per_1k, limits.unknown_output_usd_per_1k
        # This includes privacy aliases and schema text at the provider boundary.
        input_tokens = 128 + sum(
            16 + len(json.dumps(message.content, ensure_ascii=False).encode("utf-8"))
            for message in messages
        )
        output_tokens = limits.assessment_tokens if final else limits.max_planner_output_tokens
        reserve_input = 0 if final else limits.history_context_tokens + 5_000
        reserve_output = 0 if final else limits.assessment_tokens
        usd = (input_tokens * prices[0] + output_tokens * prices[1]) / 1000
        reserve_usd = (reserve_input * prices[0] + reserve_output * prices[1]) / 1000
        if self.provider_calls + (1 if final else 2) > limits.max_llm_calls:
            raise ModelBudgetStop("llm_budget")
        if self.tokens + input_tokens + output_tokens + reserve_input + reserve_output > limits.max_model_tokens:
            raise ModelBudgetStop("model_token_budget")
        if self.estimated_cost + usd + reserve_usd > limits.max_cost_usd:
            raise ModelBudgetStop("cost_budget")
        self.tokens += input_tokens + output_tokens
        self.estimated_cost += usd
        self.provider_calls += 1

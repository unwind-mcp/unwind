"""Cognitive Load Offset — ERT calculation using outgoing token count.

The Expected Response Time (ERT) stretches based on how much content
the agent last sent. A 3-word reply expects a fast response. A 400-line
script expects the user to read before responding.

This is what makes Cadence feel uncanny rather than merely clever:
same gap duration, different last-output size → different inferred state.
"""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class CognitiveLoadResult:
    """Result of cognitive load calculation."""
    base_ema_seconds: float    # Raw EMA without adjustment
    ert_seconds: float         # Adjusted ERT with cognitive load
    load_multiplier: float     # How much the ERT was stretched
    last_out_tokens: int       # Token count that drove the calculation


def compute_ert(
    base_ema_seconds: float,
    last_out_tokens: int,
    token_threshold: int = 200,
) -> CognitiveLoadResult:
    """Compute Expected Response Time with Cognitive Load Offset.

    The cognitive load offset uses logarithmic scaling:
    - At threshold (200 tokens): multiplier = 1.0 (no adjustment)
    - At 2x threshold (400 tokens): multiplier = 2.0
    - At 4x threshold (800 tokens): multiplier = 3.0
    - At 8x threshold (1600 tokens): multiplier = 4.0

    This models diminishing returns: a 1600-token response doesn't take
    8x as long to read as a 200-token response.

    Args:
        base_ema_seconds: Raw EMA for the current time bin
        last_out_tokens: Token count of the agent's last response
        token_threshold: Minimum tokens to trigger adjustment (default 200)

    Returns:
        CognitiveLoadResult with adjusted ERT
    """
    if last_out_tokens <= token_threshold or token_threshold <= 0:
        return CognitiveLoadResult(
            base_ema_seconds=base_ema_seconds,
            ert_seconds=base_ema_seconds,
            load_multiplier=1.0,
            last_out_tokens=last_out_tokens,
        )

    ratio = last_out_tokens / token_threshold
    multiplier = 1.0 + math.log2(ratio)
    ert = base_ema_seconds * multiplier

    return CognitiveLoadResult(
        base_ema_seconds=base_ema_seconds,
        ert_seconds=round(ert, 2),
        load_multiplier=round(multiplier, 4),
        last_out_tokens=last_out_tokens,
    )

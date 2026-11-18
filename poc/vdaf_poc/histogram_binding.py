"""Project a private index share from a vanilla Prio3Histogram input share.

The group commitment check is an application-protocol step, not part of the
Prio3Histogram algorithm or its validity circuit.
"""

from vdaf_poc.field import Field128
from vdaf_poc.vdaf_prio3 import Prio3Histogram


def index_share(vdaf: Prio3Histogram, ctx: bytes, agg_id: int, input_share: tuple) -> int:
    """Compute the canonical Field128 share of the 1-based selected bucket.

    Expand the same input share used by verify_init, including the Helper seed.
    Never accept a separately supplied index share from the client.
    """
    buckets, _, _ = vdaf.expand_input_share(ctx, agg_id, input_share)
    if len(buckets) != vdaf.flp.MEAS_LEN:
        raise ValueError("incorrect histogram share length")
    return sum((Field128(i + 1) * bucket for i, bucket in enumerate(buckets)), Field128(0)).int()

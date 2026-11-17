"""Experimental Prio3Histogram whose private input contains its bucket tag.

This is the VDAF circuit only. The external group commitment check is a
mandatory application protocol step before aggregating a verified output.
"""

from typing import cast

from vdaf_poc.field import Field128
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19, Histogram
from vdaf_poc.vdaf_prio3 import Prio3
from vdaf_poc.xof import XofTurboShake128


class CommitmentBoundHistogramCircuit(Histogram[Field128]):
    EVAL_OUTPUT_LEN = 3

    def __init__(self, length: int, chunk_length: int):
        super().__init__(Field128, length, chunk_length)
        self.core = Histogram(Field128, length, chunk_length)
        self.MEAS_LEN = length + 1

    def encode(self, bucket: int) -> list[Field128]:
        if bucket not in range(self.length):
            raise ValueError("bucket outside histogram")
        return super().encode(bucket) + [Field128(bucket + 1)]

    def eval(self, meas: list[Field128], joint_rand: list[Field128], num_shares: int) -> list[Field128]:
        self.check_valid_eval(meas, joint_rand)
        self.core.GADGETS = self.GADGETS
        checks = self.core.eval(meas[:-1], joint_rand, num_shares)
        tag = sum((Field128(i + 1) * meas[i] for i in range(self.length)), Field128(0))
        return checks + [meas[-1] - tag]

    def truncate(self, meas: list[Field128]) -> list[Field128]:
        if len(meas) != self.MEAS_LEN:
            raise ValueError("incorrect measurement length")
        return meas[:-1]


class Prio3CommitmentBoundHistogram(Prio3[int, list[int], Field128]):
    ID = 0xFFFF0001  # Local experimental ID. Not Prio3Histogram's ID.
    VERIFY_KEY_SIZE = 32
    xof = XofTurboShake128

    def __init__(self, length: int, chunk_length: int):
        super().__init__(2, FlpBBCGGI19(CommitmentBoundHistogramCircuit(length, chunk_length)), 1)

    def tag_share(self, ctx: bytes, agg_id: int, input_share: tuple) -> int:
        """Return this aggregator's canonical Field128 tag share."""
        share, _, _ = self.expand_input_share(ctx, agg_id, input_share)
        return cast(int, share[-1].int())

"""Projection of a private Anchor index from vanilla Prio3Histogram shares."""

import unittest
from secrets import token_bytes

from vdaf_poc.field import Field128
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19, Histogram
from vdaf_poc.histogram_binding import index_share
from vdaf_poc.vdaf import run_vdaf
from vdaf_poc.vdaf_prio3 import Prio3Histogram


class HistogramBindingTest(unittest.TestCase):
    def test_vanilla_histogram_result(self) -> None:
        vdaf = Prio3Histogram(2, 3, 2)
        self.assertEqual(vdaf.ID, 0x00000004)
        self.assertEqual(vdaf.flp.MEAS_LEN, 3)
        self.assertEqual(run_vdaf(vdaf, bytes(32), None,
                         b"quality task", [0, 1, 0, 2]), [2, 1, 1])

    def test_each_aggregator_projects_from_its_input_share(self) -> None:
        vdaf = Prio3Histogram(2, 3, 2)
        ctx = b"origin-and-label"
        public, shares = vdaf.shard(ctx, 1, token_bytes(
            vdaf.NONCE_SIZE), token_bytes(vdaf.RAND_SIZE))
        assert public is not None
        self.assertEqual(len(public), 2)
        decoded = [vdaf.decode_input_share(i, vdaf.encode_input_share(
            share)) for i, share in enumerate(shares)]
        indices = [index_share(vdaf, ctx, i, share)
                   for i, share in enumerate(decoded)]
        self.assertEqual(sum(indices) % Field128.MODULUS, 2)
        self.assertEqual(
            len(vdaf.expand_input_share(ctx, 1, decoded[1])[0]), 3)

    def test_prio3_rejects_invalid_one_hot_input(self) -> None:
        class DishonestHistogram(Histogram[Field128]):
            def encode(self, bucket: int) -> list[Field128]:
                measurement = super().encode(bucket)
                measurement[0] += Field128(1)
                return measurement

        vdaf = Prio3Histogram(2, 3, 2)
        vdaf.flp = FlpBBCGGI19(DishonestHistogram(Field128, 3, 2))
        with self.assertRaisesRegex(ValueError, "proof verifier check failed"):
            run_vdaf(vdaf, bytes(32), None, b"quality task", [1])


if __name__ == "__main__":
    unittest.main()

"""Experimental validity circuit and private tag output tests."""

import unittest
from secrets import token_bytes

from vdaf_poc.field import Field128
from vdaf_poc.vdaf import run_vdaf
from vdaf_poc.vdaf_prio3_commitment_bound import (
    CommitmentBoundHistogramCircuit,
    Prio3CommitmentBoundHistogram,
)


class CommitmentBoundHistogramTest(unittest.TestCase):
    def test_histogram_result_omits_tag(self):
        vdaf = Prio3CommitmentBoundHistogram(3, 2)
        self.assertEqual(run_vdaf(vdaf, bytes(32), None, b"quality task", [0, 1, 0, 2]), [2, 1, 1])

    def test_wrong_tag_fails_validity(self):
        circuit = CommitmentBoundHistogramCircuit(3, 2)
        valid = circuit.encode(1)
        self.assertEqual(valid[-1], Field128(2))
        valid[-1] = Field128(3)
        self.assertNotEqual(
            circuit.eval(valid, [Field128(4), Field128(5)], 1)[-1],
            Field128(0),
        )
        with self.assertRaises(ValueError):
            circuit.encode(3)

    def test_each_aggregator_gets_private_tag_share(self):
        vdaf = Prio3CommitmentBoundHistogram(3, 2)
        ctx = b"origin-and-label"
        public, shares = vdaf.shard(ctx, 1, token_bytes(vdaf.NONCE_SIZE), token_bytes(vdaf.RAND_SIZE))
        self.assertEqual(len(public), 2)
        decoded = [vdaf.decode_input_share(i, vdaf.encode_input_share(share)) for i, share in enumerate(shares)]
        tags = [vdaf.tag_share(ctx, i, share) for i, share in enumerate(decoded)]
        self.assertEqual(sum(tags) % Field128.MODULUS, 2)

    def test_prio3_rejects_client_with_wrong_tag(self):
        class DishonestCircuit(CommitmentBoundHistogramCircuit):
            def encode(self, bucket):
                measurement = super().encode(bucket)
                measurement[-1] += Field128(1)
                return measurement

        vdaf = Prio3CommitmentBoundHistogram(3, 2)
        vdaf.flp.valid = DishonestCircuit(3, 2)
        with self.assertRaisesRegex(ValueError, "proof verifier check failed"):
            run_vdaf(vdaf, bytes(32), None, b"quality task", [1])


if __name__ == "__main__":
    unittest.main()

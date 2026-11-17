# Commitment-bound Prio3Histogram: extension points

The experimental [Commitment-Bound Prio3Histogram](../../draft-vdaf-commitment-bound-histogram/draft-chris-vdaf-commitment-bound-histogram.md)
is a *new* Prio3 variant, not a change to the existing `Prio3Histogram`
algorithm or codepoint. Its validity circuit follows the histogram circuit in
Section 7.4.4, adding a private field element `t` and the linear constraint
`t = sum((i+1) * x[i])`. `Truncate` discards `t`, leaving the existing histogram
aggregate representation. Because the validity circuit has three outputs
instead of two, the query randomness used to compress validity outputs also
changes. The proof gadget and proof length need not change.

Two aggregators then perform a separate, mandatory group-commitment check on
their *untruncated* `t` shares and privately delivered blinding shares, before
accepting an output share. This protocol is outside the base VDAF interface's
`verify_init` / `verify_next` operations and requires an application-level
verification stage or a future extended VDAF interface with public inputs.
For one-round Prio3 the Leader's locally computed commitment point accompanies
its verifier share in the existing request; the Helper verifies and returns
its locally computed point with the verifier message in the existing response.
Both require Prio3 validity and commitment equality before aggregating; there
is no extra preparation round trip. These point fields and the Moderator's
assertion of acceptance of the combined MOLE presentation and DAP report are
proposed DAP integration, not ordinary VDAF or DAP behavior.
The task context, report nonce, authenticated external commitment, and both
input shares must refer to the same report. The resulting algorithm requires
its own identifier and specification; it must not be advertised as algorithm
`0x00000004` (Prio3Histogram).

Privacy against one non-colluding aggregator and correctness against malicious
clients with both aggregators executing the check are separate claims. A
corrupt aggregator can forge its group-check point, and the collector already
trusts aggregators to perform aggregation correctly in the base VDAF model.
The extension needs a composition proof and DAP integration specification
before it can be proposed as a standardized VDAF variant.
The exchanged points reveal which of the two field-carry equalities holds to
each aggregator; constant-time comparison does not hide that information.
This profile uses Field128 and one proof. Switching to Field64 would require
at least three independent proofs for this joint-randomness circuit, a new
algorithm identifier, and separate analysis.

An executable, experimental Prio3 validity circuit is in
[`poc/vdaf_poc/vdaf_prio3_commitment_bound.py`](../poc/vdaf_poc/vdaf_prio3_commitment_bound.py),
with tests in [`poc/tests/test_commitment_bound_histogram.py`](../poc/tests/test_commitment_bound_histogram.py).
It uses algorithm ID `0xffff0001` for local experiments. `tag_share()` expands
the same input share that `verify_init()` uses, including the Helper's seed.
The application-level P-256 point check and field-modulus carry handling are
in the MOLE reference code's `poc/src/ec_act/quality.py`. The point check must
be made on the report's authenticated commitment and paired with successful
Prio3 verification before either aggregator accepts an output share.

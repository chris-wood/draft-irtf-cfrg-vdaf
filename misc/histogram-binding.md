# Binding vanilla Prio3Histogram to an external commitment

The experimental [histogram commitment-binding profile](../../draft-vdaf-commitment-bound-histogram/draft-chris-vdaf-commitment-bound-histogram.md)
uses ordinary Field128 Prio3Histogram with one proof, its existing one-hot
validity circuit, input-share format, and algorithm ID `0x00000004`. It does
not extend the measurement or the VDAF proof.

For each aggregator `m`, let `x_m[i]` be the field share of bucket `i` from
the *same untruncated input share* it passes to `verify_init`. The Helper
expands its input-share seed with the normal Prio3 measurement-share domain
separator. It locally computes the canonical representative of

```
t_m = sum((i+1) * x_m[i] for i in range(n)) mod p
```

Because the verified combined histogram is one-hot, `t_0 + t_1` equals the
1-based selected bucket index modulo the Field128 modulus `p`. The
aggregators combine their locally computed group points
`P_m = int(t_m)*H + rho_m*R`, where `rho_m` is the private share of a fresh
blinding scalar. Both must require `P_0 + P_1` to equal the externally
authenticated report commitment `C` or `C + p*H` (the canonical-share carry
case), in addition to successful vanilla Prio3 verification. A client-supplied
standalone index share is not sufficient.

This point check is outside the base VDAF interface's `verify_init` /
`verify_next` operations. The Leader's point accompanies its verifier share
in the existing one-round preparation request; the Helper verifies and
returns its point with the verifier message in the existing response.
The point fields and the Moderator's authenticated assertion accepting the
combined MOLE presentation and DAP report are proposed DAP integration,
not existing DAP behavior. The VDAF algorithm ID stays `0x00000004`, while
the application protocol and DAP extensions need distinct versioning.

A corrupt aggregator can forge a commitment-check point; both aggregators
must run the check honestly for report integrity. One non-colluding aggregator
is required for individual report privacy. Exchanged points can reveal the
field-carry case to the aggregators. A composition proof and a DAP integration
specification remain necessary. Field64 is not specified here.

An executable index-share projection for ordinary `Prio3Histogram` is in
[`poc/vdaf_poc/histogram_binding.py`](../poc/vdaf_poc/histogram_binding.py),
with tests in [`poc/tests/test_histogram_binding.py`](../poc/tests/test_histogram_binding.py).
The application-level P-256 point check is in the MOLE reference code's
`poc/src/ec_act/quality.py`.

# Scoring v1: Sensitivity Analysis

## 1. Status and interpretation

Scoring v1 is an experimental, versioned risk-scoring hypothesis. Its weights
are configuration choices for an initial model, not statistically calibrated
coefficients and not validated predictors of real-world exploitation or impact.

This document records the model's analytical sensitivity and a reproducible
method for evaluating weight changes. It does not claim that an empirical
sensitivity experiment has been performed on a representative vulnerability
dataset.

## 2. Current experimental weights

| Signal | Weight |
|---|---:|
| CISA Known Exploited Vulnerabilities (KEV) | 0.70 |
| EPSS probability | 0.30 |
| Known ransomware campaign use | 0.15 |
| Total | 1.15 |

The weights are intentionally recorded exactly as implemented. They are not
normalized to sum to 1.0. The threat factor is capped at 1.0.

## 3. Scoring calculation

For each CVE, the threat factor is calculated as:

`T = min(1, w_kev * K + w_epss * P + w_ransomware * R)`

Where:

- `K` is the KEV signal.
- `P` is the EPSS probability signal.
- `R` is the ransomware campaign-use signal.
- `w_kev`, `w_epss`, and `w_ransomware` are the configured weights.

The threat uplift is applied independently to each base-severity interval bound:

`S_threat = S_base + (100 - S_base) * T`

The resulting severity interval is then adjusted by dependency exposure:

`S_operational = S_threat * E`

Here, `E` is the corresponding dependency-exposure interval. The implementation
applies each calculation independently to the lower, nominal, and upper bounds.

The final threat factor is capped at 1.0. Consequently, increasing weights
does not necessarily increase the result once the relevant threat-factor
bound has reached that cap.

## 4. Signal and uncertainty behavior

### KEV

- AVAILABLE with a record is treated as positive.
- NOT_FOUND is treated as negative.
- UNAVAILABLE and NOT_REQUESTED are treated as unknown.

### EPSS

- AVAILABLE uses the reported probability as an exact interval.
- when EPSS is not AVAILABLE, the probability is not fabricated. The interval
  is `[0, 0, 1]`, representing an unknown value bounded between zero and one.

### Ransomware campaign use

- A recorded value of `Known` is positive.
- Other values, including missing information, remain unknown.
- Unknown ransomware status is not interpreted as evidence that ransomware
  use is absent.

Unknown signals therefore preserve uncertainty in the upper threat bound.
They are not silently converted into confirmed negative evidence.

## 5. Analytical sensitivity

Before the cap becomes active, the nominal threat factor is linearly sensitive
to each signal weight:

- Increasing the KEV weight increases the nominal threat factor when KEV is
  positive.
- Increasing the EPSS weight increases the nominal threat factor when EPSS
  probability is positive.
- Increasing the ransomware weight increases the nominal threat factor when
  ransomware campaign use is known.
- A confirmed negative signal contributes zero for that signal.
- An unknown signal can widen the threat interval because its upper bound
  remains possible, even when its nominal contribution is zero.

For a fixed signal value, the uncapped nominal contribution of a weight is
proportional to that weight. This relationship stops producing additional
nominal uplift when the threat-factor cap is reached.

Dependency exposure is applied after threat uplift. It therefore scales the
resulting severity interval and can materially change operational risk even
when the underlying threat signals and weights remain unchanged.

## 6. Recommended reproducible sensitivity procedure

A future empirical evaluation should use a fixed, versioned dataset and hold
all non-weight inputs constant while changing one weight at a time.

Recommended procedure:

1. Record the baseline output using the current weights.
2. Perturb one weight at a time by -20% and +20%, keeping the other weights
   unchanged.
3. Repeat with each individual weight set to zero as an ablation scenario.
4. Recalculate lower, nominal, and upper threat and operational-risk bounds.
5. Record how often the threat-factor cap is reached.
6. Compare changes in governing CVE selection and finding-level risk ordering.
7. Repeat the analysis for available, unavailable, and unknown intelligence
   states.
8. Preserve the dataset identifier, input snapshots, weight configuration,
   software version, and results so the experiment can be reproduced.

The proposed perturbations are an evaluation protocol, not measured results.
No performance improvement or predictive validity is claimed by this document.

## 7. Interpretation and limitations

- The current weights are experimental and have not been established through
  statistical calibration or prospective validation.
- The total weight of 1.15 means the threat-factor cap can affect sensitivity.
- Missing intelligence can widen uncertainty intervals and should not be
  interpreted as confirmed absence of a threat signal.
- Sensitivity should be assessed at both CVE and finding level because the
  governing CVE is selected using operational-risk bounds.
- Dependency exposure assumptions also influence final operational risk and
  should be evaluated separately from threat-signal weights.
- Results from a sensitivity experiment describe model behavior on its chosen
  dataset; they do not, by themselves, establish real-world predictive validity.

## 8. Conclusion

Scoring v1 provides a transparent and reproducible experimental scoring
framework with explicit uncertainty intervals, source provenance, and
dependency-exposure adjustment.

Its current weights are hypotheses for evaluation, not validated coefficients.
Empirical sensitivity testing, calibration, and independent validation remain
necessary before the scores can be interpreted as validated predictions.



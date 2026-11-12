<!--
SPDX-FileCopyrightText: Portitor contributors

SPDX-License-Identifier: Apache-2.0
-->

# ADR 0009: Minimal ODRL policies

- Status: **Proposed**
- Date: 2026-11-12
- Scope: release 0.3, roadmap item "Minimal ODRL policy support: permit
  all, and one constraint type".

## Context

Offers and agreements in DSP 2025-1 are ODRL policies. Until now the
provider agreed to any request that named an offer `@id` from its catalog,
and the consumer accepted any offer and verified any agreement. This left
two gaps:

- A consumer could send a known offer `@id` with different terms (for
  example without its date limit), and the provider agreed to those terms.
- A constraint in an offer was never checked, so an offer meant to end on
  a date was agreed after that date.

Facts checked (2026-11-12):

- The DSP 2025-1 examples use `{"leftOperand": "dateTime", "operator":
  "lteq", "rightOperand": "2023-12-31T06:00Z"}`. That form has minutes but
  no seconds. The DSP JSON Schema allows the operators `eq`, `gt`, `gteq`,
  `lt`, `lteq`, `neq`, `isA`, `hasPart`, `isPartOf`, `isAllOf`, `isAnyOf`
  and `isNoneOf`, and a right operand that is a string, object or array.
  In the DSP JSON-LD context, `leftOperand` and `operator` are ODRL
  vocabulary terms.
- The ODRL 2.2 vocabulary defines `eq`, `neq`, `lt`, `lteq`, `gt` and
  `gteq` as comparisons with the right operand (W3C ODRL Vocabulary,
  section 3.16). It lists `dateTime` as a left operand. Its definition
  could not be read from this environment. From memory: "the date (and
  optional time and timezone) of exercising the action of the Rule", with
  an `xsd:date` or `xsd:dateTime` right operand. Check before 1.0.
- The DSP TCK 1.0.2 sends offers with one `use` permission and an empty
  constraint list, so the checks below keep the TCK green.

## Decision

- **One constraint type: `dateTime`**, the time the action is exercised,
  compared with "now". The operators are `eq`, `neq`, `lt`, `lteq`, `gt`
  and `gteq`. `and`, `andSequence`, `or` and `xone` combine constraints.
  Several constraints on one rule must all hold. A rule without
  constraints permits ("permit all").
- **Values.** The right operand is a date (`2030-12-31`, meaning the
  whole day, in UTC unless a time zone is given) or a date and time with a
  time zone. Seconds and a fraction are optional. A date and time without
  a time zone is refused, because it names a different instant in every
  time zone. Terms may be written short (`lteq`), prefixed (`odrl:lteq`)
  or as a full ODRL IRI.
- **Fail closed.** Any other left operand, operator or value is not
  understood, and a policy that is not understood never holds. Every part
  of a logical constraint is checked, so an unknown part is never skipped.
- **Provider.** It agrees only when two things are true. First, the
  negotiated offer has the same terms (permissions, prohibitions, duties,
  profile) as the catalog offer with that `@id`. Second, its permissions
  hold now. Otherwise it terminates the negotiation with the reason. The
  rule is in the domain, so it applies to every decider. A datasets file
  with an offer that is not understood stops the connector at start.
- **Consumer.** The default decider accepts a provider's offer only if
  its permissions hold now. It verifies an agreement only if the agreement
  has the terms of the offer it asked for or accepted. Otherwise it
  terminates the negotiation.
- **Only permissions are evaluated**, because they decide whether an
  agreement may be made now. Prohibitions and duties are terms of the
  agreement; they are compared and carried into it, but not enforced.
- The evaluator is a pure module in `portitor-dsp` (`policy`), with no new
  dependency.

## Consequences

- A known offer `@id` can no longer be used to agree to other terms. A
  consumer counter-offer with different terms is terminated by the
  default provider policy; negotiating new terms comes later.
- Terms are compared as written, except for the action name. The same
  constraint written another way (for example `odrl:lteq` instead of
  `lteq`) counts as different terms. Consumers should copy offers from the
  catalog unchanged.
- Offers that use other constraints (for example `spatial` or `purpose`)
  cannot be published until the evaluator understands them. The example
  datasets file now uses `dateTime`.
- Time comes from the host clock. A wrong clock gives wrong decisions near
  a limit, so hosts must run NTP (DEPLOYING).
- Usage control at transfer time (0.4 and later) will evaluate the
  agreement again; this ADR covers only the decision to agree.

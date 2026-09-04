"""Explanation-aware fusion and the final assessment (Task 17).

Reads everything the pipeline produced -- provider envelopes, a Task 14 graph, a
Task 15 qualification and a Task 16 reasoning result -- and answers the question
every earlier layer refused: **what assessment is justified?**

The order it works in is the order the reasoning has to happen:

1. translate provider evidence into propositions (Task 17A),
2. group claims by proposition and by genuinely independent origin,
3. read Task 16 to see which claims something actually explains,
4. apply the deterministic verdict policy,
5. decide confidence separately, and record what held it down.

Confidence is decided *after* and *apart from* the verdict, from different
inputs. Deriving one from the other would mean a MALICIOUS verdict could never
be tentative and a SUSPICIOUS one could never be firm, and both of those are
ordinary, useful things to say.

What this module does not do
----------------------------

No network, no clock, no mutation. ``as_of`` comes from Task 15; a missing
qualification is refused outright rather than papered over with a fresh
timestamp, because an assessment whose temporal reference was invented is not
reproducible. Nothing here edits evidence, a graph, a qualification or a
reasoning finding.

And no action. MALICIOUS does not mean block: shared and compromised
infrastructure make that decision genuinely difficult, and it belongs to a layer
that knows about the environment.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.enums import EvidenceEffect, MatchScope, Verdict
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import (
    ClaimAssertionStrength,
    ClaimPropositionKey,
    ClaimSemantic,
    NormalizedClaim,
)
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION, compatible
from ti_recon.reasoning.claims.registry import translate_envelope
from ti_recon.reasoning.claims.translation import (
    ClaimTranslationContext,
    ClaimTranslator,
    is_unresolved_subject,
)
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.fusion.confidence import decide_confidence
from ti_recon.reasoning.fusion.dispositions import (
    dispositions_for,
    explained_evidence_ids,
    findings_touching,
    limiting_findings,
)
from ti_recon.reasoning.fusion.independence import (
    breadth_of,
    independence_groups,
    independence_index,
)
from ti_recon.reasoning.fusion.metrics import (
    FusionMetric,
    FusionMetricsSink,
    NoOpFusionMetricsSink,
)
from ti_recon.reasoning.fusion.models import (
    ClaimContribution,
    ClaimDecisionRole,
    ClaimDisposition,
    ContributionRole,
    CorroborationGroup,
    FusionAssessment,
    FusionConflict,
    FusionIssue,
    FusionIssueType,
    PropositionGroup,
    SupportBreadth,
    assessment_id_for,
)
from ti_recon.reasoning.fusion.policy import (
    FUSION_POLICY_VERSION,
    REASON_CODES,
    VERDICT_RULES,
    decision_role_for,
    is_benign_basis,
    is_decisive_basis,
)
from ti_recon.reasoning.fusion.results import FusionCoverage, FusionResult
from ti_recon.reasoning.results import TemporalContextResult
from ti_recon.versions import ENGINE_VERSION

__all__ = ["EvidenceFusionEngine"]


@dataclass
class EvidenceFusionEngine:
    """Turns qualified, explained evidence into an assessment.

    Pure and injectable, like every other engine here. The translator registry
    and the metrics sink arrive as arguments and there is no state between runs.
    """

    translators: dict[str, ClaimTranslator] | None = None
    metrics: FusionMetricsSink = field(default_factory=NoOpFusionMetricsSink)

    def evaluate(
        self,
        *,
        qualification: TemporalContextResult,
        reasoning: FalsePositiveReasoningResult,
        results: Sequence[ProviderResultEnvelope] = (),
        graph: InvestigationGraph | None = None,
        root: IntelObject | None = None,
    ) -> FusionResult:
        """Assess one investigation.

        ``qualification`` and ``reasoning`` are both required. Fusion is
        explanation-aware by design, and running it without Task 16 would produce
        an assessment that had never asked whether its evidence had an
        alternative reading -- the exact failure the last two tasks exist to
        prevent.
        """
        target_key = self._target_key(root, results, graph)
        issues = list(self._input_issues(reasoning, results))

        claims = self._claims(results, root, graph)
        findings = reasoning.findings
        explained = explained_evidence_ids(findings)
        limited = limiting_findings(findings)

        propositions = self._propositions(claims)
        conflicts = self._conflicts(claims, propositions)
        opposed = frozenset(
            claim_id
            for conflict in conflicts
            for claim_id in (*conflict.malicious_claim_ids, *conflict.benign_claim_ids)
        )
        duplicates = self._duplicates(claims, explained)
        dispositions = dispositions_for(
            claims,
            explained=explained,
            limited=limited,
            opposed_claim_ids=opposed,
            duplicate_claim_ids=duplicates,
        )
        corroboration = self._corroboration(claims, dispositions)

        # The assessment is about `target_key`, so only claims about that subject
        # may decide it. A decisive claim about an object reached on a pivot is
        # real knowledge about *that* object; letting it into this verdict would
        # be the graph-derived promotion Task 14 deliberately deferred, arriving
        # through claim indexing instead of through an edge. Everything stays in
        # the trace, the propositions and coverage -- it just does not vote here.
        target_claims = tuple(item for item in claims if item.subject_key == target_key)
        target_corroboration = tuple(
            group for group in corroboration if group.proposition.subject_key == target_key
        )
        target_conflicts = tuple(
            conflict for conflict in conflicts if conflict.proposition.subject_key == target_key
        )
        verdict, verdict_rule, basis_claim_ids = self._decide_verdict(
            target_claims, dispositions, target_corroboration, target_conflicts
        )
        confidence, confidence_rule, caps = decide_confidence(
            verdict=verdict,
            verdict_rule_id=verdict_rule,
            claims=claims,
            dispositions=dispositions,
            corroboration=corroboration,
            conflicts=target_conflicts,
            basis_claim_ids=basis_claim_ids,
            reasoning=reasoning,
        )

        contributions = self._contributions(
            claims, dispositions, basis_claim_ids, findings, verdict, verdict_rule
        )
        issues.extend(self._claim_issues(claims))

        assessment = FusionAssessment(
            assessment_id=assessment_id_for(
                fusion_policy_version=FUSION_POLICY_VERSION,
                target_key=target_key,
                verdict=verdict,
                confidence=confidence,
                claim_ids=tuple(item.claim_id for item in claims),
                finding_ids=tuple(item.finding_id for item in findings),
                as_of=qualification.evaluated_at.isoformat(),
            ),
            target_key=target_key,
            verdict=verdict,
            confidence=confidence,
            verdict_rule_id=verdict_rule,
            confidence_rule_id=confidence_rule,
            confidence_caps=caps,
            as_of=qualification.evaluated_at,
            fusion_policy_version=FUSION_POLICY_VERSION,
            claim_semantics_policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
            qualification_policy_version=qualification.context_policy_version,
            false_positive_policy_version=reasoning.policy_version,
            engine_version=ENGINE_VERSION,
        )

        coverage = self._coverage(
            claims, dispositions, corroboration, conflicts, propositions, findings, graph
        )
        self._record(assessment, coverage)

        return FusionResult(
            target_key=target_key,
            assessment=assessment,
            normalized_claims=claims,
            proposition_groups=propositions,
            corroboration_groups=corroboration,
            conflicts=conflicts,
            contributions=contributions,
            issues=tuple(sorted(issues, key=lambda item: (item.issue_type.value, item.detail))),
            coverage=coverage,
        )

    # ------------------------------------------------------------------ #
    # Claims
    # ------------------------------------------------------------------ #

    def _claims(
        self,
        results: Sequence[ProviderResultEnvelope],
        root: IntelObject | None,
        graph: InvestigationGraph | None,
    ) -> tuple[NormalizedClaim, ...]:
        """Translate every provider result, in a fixed provider order."""
        objects: list[IntelObject] = []
        if graph is not None:
            objects.extend(node.intel_object for node in graph.nodes)
        for envelope in results:
            objects.extend(envelope.objects)

        found: list[NormalizedClaim] = []
        for envelope in sorted(results, key=lambda item: (item.provider, item.operation.value)):
            context = ClaimTranslationContext.build(
                objects=tuple(objects),
                root=root,
                source_partial=envelope.status.value in {"partial", "plan_limited"},
                policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
            )
            found.extend(translate_envelope(envelope, context, self.translators))
        return tuple(sorted(found, key=lambda item: item.claim_id))

    # ------------------------------------------------------------------ #
    # Grouping
    # ------------------------------------------------------------------ #

    def _propositions(self, claims: Sequence[NormalizedClaim]) -> tuple[PropositionGroup, ...]:
        buckets: dict[str, list[NormalizedClaim]] = defaultdict(list)
        keys: dict[str, ClaimPropositionKey] = {}
        for claim in claims:
            key = claim.proposition
            buckets[key.ref].append(claim)
            keys[key.ref] = key
        return tuple(
            PropositionGroup(
                proposition=keys[ref],
                malicious_claim_ids=tuple(
                    sorted(item.claim_id for item in members if item.is_malicious_direction)
                ),
                benign_claim_ids=tuple(
                    sorted(item.claim_id for item in members if not item.is_malicious_direction)
                ),
            )
            for ref, members in sorted(buckets.items())
        )

    def _duplicates(
        self, claims: Sequence[NormalizedClaim], explained: frozenset[str]
    ) -> frozenset[str]:
        """Claims already counted through another transport or the same lineage.

        Walked per proposition and per direction, in claim-id order so the choice
        of which member represents a group is deterministic. Explained claims are
        skipped: a claim something already accounts for is not competing to
        represent anybody.
        """
        index = independence_index(claims)
        seen: dict[tuple[str, str, str], str] = {}
        duplicates: set[str] = set()
        for claim in sorted(claims, key=lambda item: item.claim_id):
            if claim.evidence_id in explained:
                continue
            key = (claim.proposition.ref, claim.effect.value, index[claim.claim_id])
            if key in seen:
                duplicates.add(claim.claim_id)
            else:
                seen[key] = claim.claim_id
        return frozenset(duplicates)

    def _corroboration(
        self,
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
    ) -> tuple[CorroborationGroup, ...]:
        """One group per proposition and direction, over *unexplained* claims.

        Explained claims are excluded from support but retained in
        ``explained_claim_ids``, so a reader can see both what was accounted for
        and what was not without the two being mixed.
        """
        buckets: dict[tuple[str, str], list[NormalizedClaim]] = defaultdict(list)
        keys: dict[str, ClaimPropositionKey] = {}
        for claim in claims:
            buckets[(claim.proposition.ref, claim.effect.value)].append(claim)
            keys[claim.proposition.ref] = claim.proposition

        groups: list[CorroborationGroup] = []
        for (ref, effect), members in sorted(buckets.items()):
            supporting = [
                item
                for item in members
                if dispositions[item.claim_id]
                in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
            ]
            explained_here = [
                item
                for item in members
                if dispositions[item.claim_id] is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
            ]
            independence = independence_groups(supporting)
            roles = [decision_role_for(item) for item in supporting]
            strongest = None
            for candidate in (
                ClaimDecisionRole.DECISIVE,
                ClaimDecisionRole.CORROBORATIVE,
                ClaimDecisionRole.WEAK,
            ):
                if candidate in roles:
                    strongest = candidate
                    break

            groups.append(
                CorroborationGroup(
                    proposition=keys[ref],
                    effect=EvidenceEffect(effect),
                    claim_ids=tuple(sorted(item.claim_id for item in members)),
                    independence_groups=independence,
                    unexplained_claim_ids=tuple(sorted(item.claim_id for item in supporting)),
                    explained_claim_ids=tuple(sorted(item.claim_id for item in explained_here)),
                    breadth=breadth_of(independence),
                    strongest_role=strongest,
                )
            )
        return tuple(groups)

    def _conflicts(
        self,
        claims: Sequence[NormalizedClaim],
        propositions: Sequence[PropositionGroup],
    ) -> tuple[FusionConflict, ...]:
        """Genuinely opposing claims about one proposition.

        Same subject, same semantic, same scope, opposite directions. A malicious
        URL that is offline, a malicious address in a cloud range and a file that
        contacted a resolver are none of them conflicts -- those are different
        questions, and Tasks 15 and 16 already filed them as such.
        """
        by_id = {item.claim_id: item for item in claims}
        found: list[FusionConflict] = []
        for group in propositions:
            if not (group.malicious_claim_ids and group.benign_claim_ids):
                continue
            found.append(
                FusionConflict(
                    proposition=group.proposition,
                    malicious_claim_ids=group.malicious_claim_ids,
                    benign_claim_ids=group.benign_claim_ids,
                    malicious_source_families=tuple(
                        sorted({by_id[item].source_family for item in group.malicious_claim_ids})
                    ),
                    benign_source_families=tuple(
                        sorted({by_id[item].source_family for item in group.benign_claim_ids})
                    ),
                )
            )
        return tuple(found)

    # ------------------------------------------------------------------ #
    # Verdict
    # ------------------------------------------------------------------ #

    def _decide_verdict(
        self,
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
        corroboration: Sequence[CorroborationGroup],
        conflicts: Sequence[FusionConflict],
    ) -> tuple[Verdict, str, tuple[str, ...]]:
        """Apply the verdict rules in a fixed precedence.

        Returns the verdict, the rule that produced it, and the claims that
        formed its basis -- so an analyst can always ask which evidence decided
        this and get a list rather than an assurance.
        """
        supporting = {
            ClaimDisposition.UNEXPLAINED,
            ClaimDisposition.QUALIFIED_ONLY,
        }
        malicious = [
            item
            for item in claims
            if item.is_malicious_direction and dispositions[item.claim_id] in supporting
        ]
        benign = [
            item
            for item in claims
            if not item.is_malicious_direction and dispositions[item.claim_id] in supporting
        ]

        # -- MALICIOUS A: one decisive exact claim, unexplained ------------- #
        decisive = sorted(
            (item for item in malicious if is_decisive_basis(item)),
            key=lambda item: item.claim_id,
        )
        if decisive:
            return (
                Verdict.MALICIOUS,
                VERDICT_RULES["malicious_decisive"],
                tuple(item.claim_id for item in decisive),
            )

        # -- MALICIOUS B: compatible support from several independent origins #
        corroborated = self._corroborated_basis(corroboration, claims, dispositions)
        if corroborated:
            return (
                Verdict.MALICIOUS,
                VERDICT_RULES["malicious_corroborated"],
                corroborated,
            )

        # -- MALICIOUS C: two firm, compatible propositions from one origin --- #
        single_origin = self._single_origin_basis(malicious)
        if single_origin:
            return (
                Verdict.MALICIOUS,
                VERDICT_RULES["malicious_single_origin"],
                single_origin,
            )

        # -- LIKELY_BENIGN: an unopposed directional benign assertion -------- #
        benign_basis = sorted(
            (item for item in benign if is_benign_basis(item)), key=lambda item: item.claim_id
        )
        if benign_basis and not malicious:
            return (
                Verdict.LIKELY_BENIGN,
                VERDICT_RULES["likely_benign_directional"],
                tuple(item.claim_id for item in benign_basis),
            )

        # -- SUSPICIOUS / INCONCLUSIVE under a genuine conflict -------------- #
        if conflicts:
            # Re-derived from the conflicted claims rather than taken from
            # ``malicious`` above, which excludes anything marked OPPOSED.
            #
            # A conflict does not delete the malicious side. If real support
            # survives on it, that is an affirmative reason for concern and the
            # verdict says so, with the disagreement recorded and confidence
            # capped. Reading only the unopposed set would have made this branch
            # unreachable and quietly turned every genuine disagreement into a
            # shrug -- which is cancellation by omission.
            conflicted = {
                claim_id for conflict in conflicts for claim_id in conflict.malicious_claim_ids
            }
            residual = [
                item
                for item in claims
                if (item.claim_id in conflicted or item in malicious)
                and dispositions[item.claim_id] is not ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
                and item.is_malicious_direction
                and decision_role_for(item) is not ClaimDecisionRole.WEAK
            ]
            if residual:
                return (
                    Verdict.SUSPICIOUS,
                    VERDICT_RULES["suspicious_conflict"],
                    tuple(sorted(item.claim_id for item in residual)),
                )
            return (Verdict.INCONCLUSIVE, VERDICT_RULES["inconclusive_conflict"], ())

        # -- SUSPICIOUS: affirmative residual concern ------------------------ #
        if malicious:
            return (
                Verdict.SUSPICIOUS,
                VERDICT_RULES["suspicious_residual"],
                tuple(sorted(item.claim_id for item in malicious)),
            )

        # -- LIKELY_BENIGN: every malicious claim specifically explained ----- #
        #
        # The narrow path. It requires at least one malicious claim to have been
        # explained by an exact-object Task 16 alternative explanation, and no
        # malicious claim left over. Context alone can never reach here: a
        # warninglist hit produces no explanation, so there is nothing to satisfy
        # the first condition.
        explained_any = any(
            item.is_malicious_direction
            and dispositions[item.claim_id] is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
            for item in claims
        )
        if explained_any:
            return (
                Verdict.LIKELY_BENIGN,
                VERDICT_RULES["likely_benign_explained"],
                tuple(
                    sorted(
                        item.claim_id
                        for item in claims
                        if dispositions[item.claim_id] is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
                    )
                ),
            )

        # -- INCONCLUSIVE: nothing pointed anywhere --------------------------- #
        return (Verdict.INCONCLUSIVE, VERDICT_RULES["inconclusive_no_support"], ())

    def _corroborated_basis(
        self,
        corroboration: Sequence[CorroborationGroup],
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
    ) -> tuple[str, ...]:
        """Malicious support from several genuinely independent origins.

        Compatibility is required across the origins, not merely direction: two
        sources both saying "malicious" about different propositions have not
        corroborated each other, and this is where Task 16's scanner/C2 problem
        stays solved. Weak semantics cannot participate at all.
        """
        by_id = {item.claim_id: item for item in claims}
        index = independence_index(claims)
        for group in corroboration:
            if group.effect is not EvidenceEffect.SUPPORTS_MALICIOUS:
                continue
            if group.breadth is not SupportBreadth.MULTIPLE_INDEPENDENT_SOURCES:
                continue
            members = [by_id[item] for item in group.unexplained_claim_ids]
            usable = [
                item
                for item in members
                if decision_role_for(item) is not ClaimDecisionRole.WEAK
                and dispositions[item.claim_id]
                in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
            ]
            # Independence components, not families: a relay can cross a family
            # boundary while naming the same origin, and counting families would
            # read that one source as two.
            origins = {index[item.claim_id] for item in usable}
            if len(usable) >= 2 and len(origins) >= 2:
                return tuple(sorted(item.claim_id for item in usable))

        # Support may also arrive as compatible claims across *different*
        # propositions about the same subject -- a repository holding the sample
        # and a sandbox watching it act. The compatibility table decides, never
        # a name comparison.
        return self._compatible_cross_proposition(claims, dispositions)

    def _single_origin_basis(self, malicious: Sequence[NormalizedClaim]) -> tuple[str, ...]:
        """Two different firm propositions about the exact object, one origin.

        What this recognises is *kinds* of knowledge, not records: a curated
        verdict that the object is malicious and a sandbox's classification of
        the same object are different questions with compatible answers, and
        one source having answered both firmly is more than one source having
        said "malicious" once. What it refuses to recognise is repetition -- ten
        sandbox records are one proposition, an aggregate never participates,
        a hedged claim never participates, and nothing at host scope
        participates. A single firm reputation claim, or a single firm sandbox
        classification, still stops at SUSPICIOUS.
        """
        usable = sorted(
            (
                item
                for item in malicious
                if item.scope in {MatchScope.EXACT_OBSERVABLE}
                and decision_role_for(item) is ClaimDecisionRole.CORROBORATIVE
                and item.strength is ClaimAssertionStrength.ASSERTED
            ),
            key=lambda item: item.claim_id,
        )
        index = independence_index(usable) if usable else {}
        for position, first in enumerate(usable):
            for second in usable[position + 1 :]:
                if first.subject_key != second.subject_key:
                    continue
                if first.semantic is second.semantic:
                    continue
                if index[first.claim_id] != index[second.claim_id]:
                    # Different origins are the independent-corroboration rule's
                    # business, and it has already declined.
                    continue
                if compatible(first.semantic, second.semantic):
                    return (first.claim_id, second.claim_id)
        return ()

    def _compatible_cross_proposition(
        self,
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
    ) -> tuple[str, ...]:
        usable = sorted(
            (
                item
                for item in claims
                if item.is_malicious_direction
                and decision_role_for(item) is not ClaimDecisionRole.WEAK
                and dispositions[item.claim_id]
                in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
            ),
            key=lambda item: item.claim_id,
        )
        index = independence_index(claims)
        for position, first in enumerate(usable):
            for second in usable[position + 1 :]:
                if first.subject_key != second.subject_key:
                    continue
                if first.scope is not second.scope:
                    # Same subject, different scope: not the same thing being
                    # claimed. A host-level reputation beside an exact-URL
                    # finding is about the neighbourhood, and letting the two
                    # corroborate would complete a verdict about the exact
                    # artifact out of a statement nobody made about it -- the
                    # mirror of the rule that host context never clears an exact
                    # URL. Within one proposition scope already matches, because
                    # it is part of the proposition key.
                    continue
                if index[first.claim_id] == index[second.claim_id]:
                    continue
                if compatible(first.semantic, second.semantic):
                    return (first.claim_id, second.claim_id)
        return ()

    # ------------------------------------------------------------------ #
    # Trace
    # ------------------------------------------------------------------ #

    def _contributions(
        self,
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
        basis_claim_ids: tuple[str, ...],
        findings: Sequence[object],
        verdict: Verdict,
        verdict_rule: str,
    ) -> tuple[ClaimContribution, ...]:
        """Why each claim mattered, or why it did not.

        Every claim gets a contribution, including the ones that were explained
        away and the ones that were already counted. A trace that listed only
        what supported the verdict would be an argument rather than a record.
        """
        basis = set(basis_claim_ids)
        found: list[ClaimContribution] = []
        for claim in claims:
            disposition = dispositions[claim.claim_id]
            role, codes = self._role_for(
                claim, disposition, claim.claim_id in basis, verdict, verdict_rule
            )
            found.append(
                ClaimContribution(
                    claim_id=claim.claim_id,
                    evidence_id=claim.evidence_id,
                    role=role,
                    disposition=disposition,
                    decision_role=decision_role_for(claim),
                    semantic=claim.semantic,
                    effect=claim.effect,
                    scope=claim.scope,
                    source_family=claim.source_family,
                    proposition_ref=claim.proposition.ref,
                    reasoning_finding_ids=findings_touching(findings, claim.evidence_id),  # type: ignore[arg-type]
                    reason_codes=codes,
                )
            )
        return tuple(sorted(found, key=lambda item: item.claim_id))

    def _role_for(
        self,
        claim: NormalizedClaim,
        disposition: ClaimDisposition,
        in_basis: bool,
        verdict: Verdict,
        verdict_rule: str,
    ) -> tuple[ContributionRole, tuple[str, ...]]:
        codes: list[str] = []
        if claim.source_partial:
            codes.append(REASON_CODES["partial"])
        if claim.scope is not claim.scope.EXACT_OBSERVABLE:
            codes.append(REASON_CODES["scope_limited"])

        if disposition is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE:
            codes.append(REASON_CODES["explained"])
            return ContributionRole.EXPLAINED_NOT_RELIED_UPON, tuple(sorted(codes))
        if disposition is ClaimDisposition.DEPENDENT_DUPLICATE:
            codes.append(REASON_CODES["dependent"])
            return ContributionRole.DEPENDENT_CORROBORATION, tuple(sorted(codes))
        if disposition is ClaimDisposition.OPPOSED and not in_basis:
            codes.append(REASON_CODES["opposed"])
            return ContributionRole.OPPOSES_VERDICT, tuple(sorted(codes))
        if disposition is ClaimDisposition.QUALIFIED_ONLY:
            codes.append(REASON_CODES["qualified"])

        if in_basis:
            role = decision_role_for(claim)
            if role is ClaimDecisionRole.DECISIVE:
                codes.append(REASON_CODES["decisive_basis"])
            elif verdict_rule == VERDICT_RULES["malicious_single_origin"]:
                codes.append(REASON_CODES["compatible_same_origin"])
            else:
                codes.append(REASON_CODES["corroborates"])
            return ContributionRole.SUPPORTS_VERDICT, tuple(sorted(codes))

        if decision_role_for(claim) is ClaimDecisionRole.WEAK:
            codes.append(REASON_CODES["weak_support"])
            return ContributionRole.LIMITS_CONFIDENCE, tuple(sorted(codes))

        # Directional, unexplained, and not what the rule keyed on. Still real
        # support and still visible -- never silently dropped.
        opposing = (verdict is Verdict.LIKELY_BENIGN and claim.is_malicious_direction) or (
            verdict is Verdict.MALICIOUS and not claim.is_malicious_direction
        )
        if opposing:
            codes.append(REASON_CODES["opposed"])
            return ContributionRole.OPPOSES_VERDICT, tuple(sorted(codes))
        return ContributionRole.SUPPORTS_VERDICT, tuple(sorted(codes))

    # ------------------------------------------------------------------ #
    # Inputs, coverage, metrics
    # ------------------------------------------------------------------ #

    def _target_key(
        self,
        root: IntelObject | None,
        results: Sequence[ProviderResultEnvelope],
        graph: InvestigationGraph | None,
    ) -> str:
        if root is not None:
            return root.canonical_key
        if graph is not None and graph.root_key:
            return graph.root_key
        for envelope in sorted(results, key=lambda item: item.provider):
            if envelope.objects:
                return envelope.objects[0].canonical_key
        return "unknown"

    def _input_issues(
        self,
        reasoning: FalsePositiveReasoningResult,
        results: Sequence[ProviderResultEnvelope],
    ) -> tuple[FusionIssue, ...]:
        """Detect inputs that describe different investigations.

        A Task 16 finding referencing evidence this run never saw means the two
        results are not about the same thing, and fusing them would produce an
        assessment assembled from two unrelated pictures. Recorded explicitly
        rather than silently ignored.
        """
        known = {item.id for envelope in results for item in envelope.evidence}
        unknown = sorted(
            {
                link.ref
                for finding in reasoning.findings
                for link in finding.links
                if link.target.value == "evidence" and link.ref not in known
            }
        )
        if not unknown:
            return ()
        return (
            FusionIssue(
                issue_type=FusionIssueType.INPUT_REFERENCE_MISMATCH,
                detail=f"{len(unknown)} reasoning reference(s) name evidence not in this run",
                refs=tuple(unknown[:20]),
            ),
        )

    def _claim_issues(self, claims: Sequence[NormalizedClaim]) -> tuple[FusionIssue, ...]:
        found: list[FusionIssue] = []
        unmapped = sorted(
            item.claim_id
            for item in claims
            if item.semantic is ClaimSemantic.UNCLASSIFIED_DIRECTIONAL
        )
        if unmapped:
            found.append(
                FusionIssue(
                    issue_type=FusionIssueType.UNMAPPED_DIRECTIONAL_CLAIM,
                    detail=f"{len(unmapped)} directional claim(s) have no semantic mapping",
                    refs=tuple(unmapped[:20]),
                )
            )

        # A claim naming an object this run never saw. It stays in the trace and
        # is named here rather than being quietly attributed to the root.
        orphaned = sorted(
            item.claim_id for item in claims if is_unresolved_subject(item.subject_key)
        )
        if orphaned:
            found.append(
                FusionIssue(
                    issue_type=FusionIssueType.UNRESOLVED_CLAIM_SUBJECT,
                    detail=(
                        f"{len(orphaned)} claim(s) name a subject object this run never saw; "
                        "they are retained and excluded from the assessment"
                    ),
                    refs=tuple(orphaned[:20]),
                )
            )
        return tuple(found)

    def _coverage(
        self,
        claims: Sequence[NormalizedClaim],
        dispositions: dict[str, ClaimDisposition],
        corroboration: Sequence[CorroborationGroup],
        conflicts: Sequence[FusionConflict],
        propositions: Sequence[PropositionGroup],
        findings: Sequence[object],
        graph: InvestigationGraph | None,
    ) -> FusionCoverage:
        return FusionCoverage(
            directional_evidence_examined=len({item.evidence_id for item in claims}),
            claims_normalized=len(claims),
            claims_unclassified=sum(
                1 for item in claims if item.semantic is ClaimSemantic.UNCLASSIFIED_DIRECTIONAL
            ),
            propositions=len(propositions),
            independent_support_groups=sum(
                group.independent_support_group_count for group in corroboration
            ),
            explained_directional_claims=sum(
                1
                for item in claims
                if dispositions[item.claim_id] is ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
            ),
            unexplained_directional_claims=sum(
                1
                for item in claims
                if dispositions[item.claim_id]
                in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
            ),
            benign_directional_claims=sum(1 for item in claims if not item.is_malicious_direction),
            conflicts=len(conflicts),
            partial_sources=len({item.source_family for item in claims if item.source_partial}),
            reasoning_findings_consumed=len(findings),
            graph_relationships_examined=0 if graph is None else graph.edge_count,
        )

    def _record(self, assessment: FusionAssessment, coverage: FusionCoverage) -> None:
        self.metrics.record_fusion(
            FusionMetric(
                verdict=assessment.verdict.value,
                confidence=assessment.confidence.value,
                verdict_rule=assessment.verdict_rule_id,
                confidence_rule=assessment.confidence_rule_id,
                claims_normalized=coverage.claims_normalized,
                claims_unclassified=coverage.claims_unclassified,
                conflicts=coverage.conflicts,
                unexplained_directional_claims=coverage.unexplained_directional_claims,
            )
        )

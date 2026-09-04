"""A related object the graph cannot hold costs one node, never the run (Task 24).

A DEEP GTI lookup of a real sample returned a contacted URL whose canonical key
was longer than a graph node may carry, and the model refused it with a
validation error that ended the whole investigation as an internal failure. A
provider can return a related URL of any length; the bound is the graph's, so
the graph enforces it -- the object is refused, recorded once, and every
relationship naming it goes with it.
"""

from __future__ import annotations

from fixtures.correlation import DIGEST_A, envelope, file_object, graph_for, observable
from ti_recon.correlation.models import MAX_NODE_KEY_LENGTH, CorrelationIssueType
from ti_recon.enums import RelationshipType

LONG_URL = "https://example.test/" + "a" * (MAX_NODE_KEY_LENGTH + 40)


def test_an_over_long_related_object_is_refused_and_recorded_once() -> None:
    graph, engine = graph_for()
    sample = file_object(sha256=DIGEST_A)
    contacted = observable(LONG_URL)
    short = observable("https://example.test/short")
    summary = engine.ingest(
        envelope(
            "sandbox",
            objects=(sample, contacted, short),
            links=(
                (sample, RelationshipType.CONTACTS, contacted, "http_conversations"),
                (sample, RelationshipType.CONTACTS, short, "http_conversations"),
            ),
        )
    )

    refused = [
        issue
        for issue in summary.issues
        if issue.issue_type is CorrelationIssueType.INVALID_RELATED_OBJECT
    ]
    assert len(refused) == 1
    assert refused[0].provider_id == "sandbox"
    assert "url" in refused[0].detail
    assert LONG_URL not in refused[0].detail
    assert refused[0].node_keys == ()
    assert all(len(key) <= MAX_NODE_KEY_LENGTH for key in (node.node_key for node in graph.nodes))
    # The relationship naming the refused object went with it, without being
    # reported as dangling: the object was refused, not absent.
    assert not any(
        issue.issue_type is CorrelationIssueType.DANGLING_RELATIONSHIP for issue in summary.issues
    )
    # The rest of the result is untouched.
    assert summary.nodes_added == 2
    assert summary.edges_added == 1


def test_the_bound_is_the_models_own() -> None:
    from pydantic import ValidationError

    from ti_recon.correlation.models import GraphNode

    node = GraphNode(node_key="k" * MAX_NODE_KEY_LENGTH, intel_object=observable(LONG_URL))
    assert len(node.node_key) == MAX_NODE_KEY_LENGTH
    try:
        GraphNode(node_key="k" * (MAX_NODE_KEY_LENGTH + 1), intel_object=observable(LONG_URL))
    except ValidationError:
        return
    raise AssertionError("the model accepted a key beyond the bound the engine enforces")

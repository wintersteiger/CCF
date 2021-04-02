# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import os
from loguru import logger as LOG


def action(name, **args):
    return {"name": name, "args": args}


def proposal(*actions):
    return {"actions": list(actions)}


def merge(*proposals):
    return {"actions": sum((prop["actions"] for prop in proposals), [])}


valid_set_recovery_threshold = proposal(
    action("set_recovery_threshold", recovery_threshold=5)
)
valid_set_recovery_threshold_twice = merge(
    valid_set_recovery_threshold, valid_set_recovery_threshold
)
always_accept_noop = proposal(action("always_accept_noop"))
always_reject_noop = proposal(action("always_reject_noop"))
always_accept_with_one_vote = proposal(action("always_accept_with_one_vote"))
always_reject_with_one_vote = proposal(action("always_reject_with_one_vote"))
always_accept_if_voted_by_operator = proposal(
    action("always_accept_if_voted_by_operator")
)
always_accept_if_proposed_by_operator = proposal(
    action("always_accept_if_proposed_by_operator")
)
always_accept_with_two_votes = proposal(action("always_accept_with_two_votes"))
always_reject_with_two_votes = proposal(action("always_reject_with_two_votes"))


@reqs.description("Test proposal validation")
def test_proposal_validation(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals.js",
            proposal(action("valid_pem", pem="That's not a PEM")),
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        with open(os.path.join(network.common_dir, "networkcert.pem"), "r") as cert:
            valid_pem = cert.read()

        r = c.post(
            "/gov/proposals.js",
            proposal(action("valid_pem", pem=valid_pem)),
        )
        assert r.status_code == 200

    return network


@reqs.description("Test proposal storage")
def test_proposal_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.get("/gov/proposals.js/42")
        assert r.status_code == 404, r.body.text()

        r = c.get("/gov/proposals.js/42/actions")
        assert r.status_code == 404, r.body.text()

        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            r = c.get(f"/gov/proposals.js/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.get(f"/gov/proposals.js/{proposal_id}/actions")
            assert r.status_code == 200, r.body.text()
            assert r.body.json() == prop, r.body.json()

    return network


@reqs.description("Test proposal withdrawal")
def test_proposal_withdrawal(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals.js/42/withdraw")
            assert r.status_code == 400, r.body.text()

            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            with node.client(None, "member1") as oc:
                r = oc.post(f"/gov/proposals.js/{proposal_id}/withdraw")
                assert r.status_code == 403, r.body.text()

            r = c.get(f"/gov/proposals.js/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Withdrawn",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

    return network


@reqs.description("Test ballot storage and validation")
def test_ballot_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposal_id"]

        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", {})
        assert r.status_code == 400, r.body.text()

        ballot = {
            "ballot": "export function vote (proposal, proposer_id) { return true }"
        }
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()

        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.get(f"/gov/proposals.js/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json() == ballot, r.body.json()

    with node.client(None, "member1") as c:
        ballot = {
            "ballot": "export function vote (proposal, proposer_id) { return false }"
        }
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        member_id = network.consortium.get_member_by_local_id("member1").service_id
        r = c.get(f"/gov/proposals.js/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json() == ballot

    return network


@reqs.description("Test pure proposals")
def test_pure_proposals(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        for prop, state in [
            (always_accept_noop, "Accepted"),
            (always_reject_noop, "Rejected"),
        ]:
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {
                "ballot": "export function vote (proposal, proposer_id) { return true }"
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 400, r.body.text()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

    return network


def opposite(js_bool):
    if js_bool == "true":
        return "false"
    elif js_bool == "false":
        return "true"
    else:
        raise ValueError(f"{js_bool} is not a JavaScript boolean")


@reqs.description("Test vote proposals")
def test_proposals_with_votes(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        for prop, state, direction in [
            (always_accept_with_one_vote, "Accepted", "true"),
            (always_reject_with_one_vote, "Rejected", "false"),
        ]:
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {
                "ballot": f"export function vote (proposal, proposer_id) {{ return {direction} }}"
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            member_id = network.consortium.get_member_by_local_id("member0").service_id
            ballot = {
                "ballot": f'export function vote (proposal, proposer_id) {{ if (proposer_id == "{member_id}") {{ return {direction} }} else {{ return {opposite(direction) } }} }}'
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

    with node.client(None, "member0") as c:
        for prop, state, direction in [
            (always_accept_with_two_votes, "Accepted", "true"),
            (always_reject_with_two_votes, "Rejected", "false"),
        ]:
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {
                "ballot": f"export function vote (proposal, proposer_id) {{ return {direction} }}"
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()

            with node.client(None, "member1") as oc:
                ballot = {
                    "ballot": f"export function vote (proposal, proposer_id) {{ return {direction} }}"
                }
                r = oc.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
                assert r.status_code == 200, r.body.text()
                assert r.body.json()["state"] == state, r.body.json()

    return network


@reqs.description("Test operator proposals and votes")
def test_operator_proposals_and_votes(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", always_accept_if_voted_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

        ballot = {
            "ballot": "export function vote (proposal, proposer_id) { return true; }"
        }
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", always_accept_if_proposed_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

    return network


@reqs.description("Test actions")
def test_actions(network, args):
    node = network.find_random_node()

    # Rekey ledger
    network.consortium.trigger_ledger_rekey(node)

    # Add new user twice (with and without user data)
    new_user_local_id = "js_user"
    new_user = network.create_user(new_user_local_id, args.participants_curve)
    LOG.info(f"Adding new user {new_user.service_id}")

    user_data = None
    network.consortium.add_user(node, new_user.local_id, user_data)

    user_data = {"foo": "bar"}
    network.consortium.add_user(node, new_user.local_id, user_data)

    with node.client(new_user.local_id) as c:
        r = c.post("/app/log/private", {"id": 0, "msg": "JS"})
        assert r.status_code == 200, r.body.text()

    # Set user data
    network.consortium.set_user_data(
        node, new_user.service_id, user_data={"user": "data"}
    )
    network.consortium.set_user_data(node, new_user.service_id, user_data=None)

    # Remove user
    network.consortium.remove_user(node, new_user.service_id)

    with node.client(new_user.local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == 401, r.body.text()

    # Set member data
    network.consortium.set_member_data(
        node,
        network.consortium.get_member_by_local_id("member0").service_id,
        member_data={"is_admin": True},
    )

    # Set recovery threshold
    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=0)
        assert False, "Recovery threshold cannot be set to zero"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=256)
        assert False, "Recovery threshold cannot be set to > 255"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=None)
        assert False, "Recovery threshold value must be passed as proposal argument"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(
            node,
            recovery_threshold=len(network.consortium.get_active_recovery_members())
            + 1,
        )
        assert (
            False
        ), "Recovery threshold cannot be greater than the number of active recovery members"
    except infra.proposal.ProposalNotAccepted:
        pass

    network.consortium.set_recovery_threshold(
        node, recovery_threshold=network.consortium.recovery_threshold - 1
    )

    # Refresh recovery shares
    network.consortium.trigger_recovery_shares_refresh(node)

    # Set member
    new_member = network.consortium.generate_and_add_new_member(
        node, args.participants_curve
    )

    member_data = {"foo": "bar"}
    new_member = network.consortium.generate_and_add_new_member(
        node, args.participants_curve, member_data=member_data
    )

    # Remove member
    network.consortium.remove_member(node, new_member)
    network.consortium.remove_member(node, new_member)


@reqs.description("Test apply")
def test_apply(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals.js",
            proposal(action("always_throw_in_apply")),
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Failed", r.body.json()
        assert (
            r.body.json()["failure_reason"] == "Failed to apply(): Error: Error message"
        ), r.body.json()

    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals.js",
            proposal(action("always_throw_in_resolve")),
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Failed", r.body.json()
        assert (
            r.body.json()["failure_reason"]
            == "Failed to resolve(): Error: Resolve message"
        ), r.body.json()

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_proposal_validation(network, args)
        network = test_proposal_storage(network, args)
        network = test_proposal_withdrawal(network, args)
        network = test_ballot_storage(network, args)
        network = test_pure_proposals(network, args)
        network = test_proposals_with_votes(network, args)
        network = test_operator_proposals_and_votes(network, args)
        network = test_apply(network, args)
        network = test_actions(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = ["local://localhost"]
    args.initial_user_count = 2
    run(args)
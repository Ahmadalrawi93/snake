"""Generate bounded, non-executable manual authorization validation plans."""
import hashlib
from app.schemas.authorization_test_cases import AuthorizationTestCaseReport, ManualAuthorizationTestCase

def _case(category, host, resource, objective, refs, *, state_change=False):
    identity="|".join([category,host,resource,*sorted(refs)])
    case_id=hashlib.sha256(identity.encode()).hexdigest()[:20]
    common=[
        "Confirm the exact host, routes, accounts, and test data are explicitly covered by the program authorization.",
        "Use only program-designated test identities and records; do not access real user or third-party data.",
        "Have the program's written rules available and stop if the required account or permission is not explicitly authorized.",
    ]
    steps=[
        "Review the linked passive route observations and map each route to its documented business purpose.",
        "Establish the expected access policy with program documentation or the application owner before testing.",
        "Using only the designated test identities, compare the documented permitted and denied access cases without expanding scope.",
        "Record the server's observed allow/deny result and preserve minimal redacted evidence; do not infer behavior from UI visibility.",
    ]
    if state_change:
        steps.insert(3,"Perform a state-changing action only when the program explicitly permits that exact action and the test record is disposable.")
    expected=[
        "The server enforces authorization independently of client-side controls.",
        "Denied access does not disclose protected object contents or permit unauthorized state changes.",
        "The response and resulting state match the documented policy for the designated test identities.",
    ]
    return ManualAuthorizationTestCase(
        case_id=case_id,category=category,host=host,resource=resource,objective=objective,
        prerequisites=common,manual_steps=steps,expected_secure_behavior=expected,
        evidence_to_record=[
            "Program authorization and the relevant policy excerpt.",
            "Test identity roles and ownership context, with secrets and personal data redacted.",
            "Minimal request/response evidence captured through the approved testing process.",
            "Before/after state for disposable test records when state changes are explicitly permitted.",
            "Observation IDs linking this plan to the passive discovery evidence.",
        ],
        supporting_observation_ids=sorted(set(refs))[:500],
    )

def build_authorization_test_case_report(*, boundary=None, tenant=None, cross_endpoint=None, workflow=None, max_cases=1000):
    if not 1 <= max_cases <= 2000:
        raise ValueError("invalid authorization test case limit")
    cases=[]
    for item in getattr(boundary,"hypotheses",[]):
        refs=item.supporting_observation_ids
        if "object_reference_surface_observed" in item.review_reasons:
            cases.append(_case("object_ownership",item.host,item.resource,
                "Compare server-side object ownership enforcement across the observed collection and object-reference routes.",refs))
        if "privileged_and_ordinary_surfaces_coexist" in item.review_reasons or "role_or_permission_surface_observed" in item.review_reasons:
            cases.append(_case("role_boundary",item.host,item.resource,
                "Compare effective server-side role restrictions across privileged and ordinary route surfaces.",refs,state_change=True))
    for item in getattr(tenant,"hypotheses",[]):
        cases.append(_case("cross_tenant",item.host,item.resource,
            "Verify tenant isolation using only two program-designated test tenants and disposable records.",item.supporting_observation_ids))
    for item in getattr(cross_endpoint,"hypotheses",[]):
        kinds={x.operation_kind for x in item.operations}
        if "bulk" in kinds:
            cases.append(_case("bulk_authorization",item.host,item.resource,
                "Review whether bulk operations enforce authorization independently for each designated test object.",item.supporting_observation_ids,state_change=True))
        if "export" in kinds:
            cases.append(_case("export_authorization",item.host,item.resource,
                "Compare export/download authorization with the corresponding object and collection access policy.",item.supporting_observation_ids))
        cases.append(_case("cross_endpoint_consistency",item.host,item.resource,
            "Compare documented authorization behavior across all observed endpoint operation surfaces.",item.supporting_observation_ids,state_change=True))
    for item in getattr(workflow,"hypotheses",[]):
        cases.append(_case("workflow_transition",item.host,item.resource,
            "Review authorization and documented state preconditions for the observed business-operation routes.",item.supporting_observation_ids,state_change=True))
    unique={case.case_id:case for case in cases}
    ordered=[unique[key] for key in sorted(unique)]
    if len(ordered)>max_cases:
        raise ValueError("authorization test case limit exceeded")
    return AuthorizationTestCaseReport(cases=ordered)

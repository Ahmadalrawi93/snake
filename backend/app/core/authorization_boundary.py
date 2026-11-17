"""Build manual authorization-boundary review leads from passive URL observations."""
from collections import defaultdict
from urllib.parse import urlsplit
from app.schemas.analysis_context import AnalysisContext
from app.schemas.authorization_boundary import AuthorizationBoundaryHypothesis, AuthorizationBoundaryReport, AuthorizationSurface

PRIVILEGED = {"admin", "administrator", "staff", "moderator", "manage", "management", "internal", "superuser"}
ROLE_MARKERS = {"role", "roles", "permission", "permissions", "acl", "policy", "policies"}
RESOURCE = {"user":"users", "users":"users", "account":"accounts", "accounts":"accounts",
    "order":"orders", "orders":"orders", "invoice":"invoices", "invoices":"invoices",
    "payment":"payments", "payments":"payments", "document":"documents", "documents":"documents",
    "file":"files", "files":"files", "project":"projects", "projects":"projects",
    "organization":"organizations", "organizations":"organizations", "team":"teams", "teams":"teams"}
def _surface(path, ids):
    parts=[p.lower() for p in path.split("/") if p]
    markers=sorted(set(parts).intersection(PRIVILEGED | ROLE_MARKERS))
    object_ref=any(p in {"{id}", ":id", "{uuid}", ":uuid"} or p.isdigit() or
                   (len(p)>=16 and all(c in "0123456789abcdef-" for c in p)) for p in parts)
    if markers and set(markers).intersection(PRIVILEGED):
        kind="privileged"
    elif set(markers).intersection(ROLE_MARKERS):
        kind="privileged"
    elif object_ref:
        kind="object_reference"
    else:
        kind="ordinary"
    return AuthorizationSurface(route_template=path, surface_kind=kind,
        markers=markers or (["object_reference"] if object_ref else ["ordinary_route"]),
        observation_ids=ids)
def build_authorization_boundary_report(context: AnalysisContext, *, max_hypotheses: int=500):
    if not 1 <= max_hypotheses <= 1000:
        raise ValueError("invalid authorization report limit")
    grouped=defaultdict(dict)
    observations=[o for g in context.groups for o in g.observations]+context.ungrouped
    for item in observations:
        if item.kind!="url": continue
        try:
            parsed=urlsplit(item.value)
            if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: continue
            host=(item.host_key or parsed.hostname).lower().rstrip(".")
            parts=[p.lower() for p in parsed.path.split("/") if p]
            resource=next((RESOURCE[p] for p in parts if p in RESOURCE),None)
            if not resource: continue
            route="/" + "/".join(parts)
            grouped[(host,resource)][route]=sorted(set(item.observation_ids))
        except ValueError: continue
    result=[]
    for (host,resource),routes in sorted(grouped.items()):
        surfaces=[_surface(route,ids) for route,ids in sorted(routes.items())]
        kinds={s.surface_kind for s in surfaces}
        reasons=[]
        if "privileged" in kinds and ("ordinary" in kinds or "object_reference" in kinds):
            reasons.append("privileged_and_ordinary_surfaces_coexist")
        if "object_reference" in kinds:
            reasons.append("object_reference_surface_observed")
        if any(set(s.markers).intersection(ROLE_MARKERS) for s in surfaces):
            reasons.append("role_or_permission_surface_observed")
        if not reasons: continue
        refs=sorted({ref for s in surfaces for ref in s.observation_ids})[:500]
        result.append(AuthorizationBoundaryHypothesis(host=host,resource=resource,
            surfaces=surfaces[:30],review_reasons=reasons,
            validation_questions=[
                "Does every route enforce authentication server-side, including direct API access?",
                "Are privileged operations restricted by server-verified roles rather than client-side UI state?",
                "Is object ownership or tenant membership checked for every referenced object?",
                "Can a lower-privileged test account access or modify another account's object?",
                "Are role and permission changes protected against self-escalation and stale sessions?",
                "Do alternate API versions and internal routes enforce the same authorization policy?",
            ],supporting_observation_ids=refs))
    result.sort(key=lambda x:(x.host,x.resource))
    if len(result)>max_hypotheses: raise ValueError("authorization report limit exceeded")
    return AuthorizationBoundaryReport(hypotheses=result)

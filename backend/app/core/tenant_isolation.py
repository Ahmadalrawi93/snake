"""Identify passive route patterns that merit manual cross-tenant isolation review."""
from collections import defaultdict
from urllib.parse import urlsplit
from app.schemas.analysis_context import AnalysisContext
from app.schemas.tenant_isolation import TenantIsolationHypothesis, TenantIsolationReport, TenantRouteEvidence

TENANT_MARKERS={"tenant","tenants","org","orgs","organization","organizations","workspace","workspaces","team","teams","account","accounts"}
RESOURCES={"project":"projects","projects":"projects","user":"users","users":"users","order":"orders","orders":"orders",
 "invoice":"invoices","invoices":"invoices","payment":"payments","payments":"payments","document":"documents","documents":"documents",
 "file":"files","files":"files","member":"members","members":"members","subscription":"subscriptions","subscriptions":"subscriptions",
 "report":"reports","reports":"reports","setting":"settings","settings":"settings","api-key":"api-keys","api-keys":"api-keys"}
def _object_ref(parts):
    return any(p in {"{id}",":id","{uuid}",":uuid"} or p.isdigit() or
        (len(p)>=16 and all(ch in "0123456789abcdef-" for ch in p)) for p in parts)
def build_tenant_isolation_report(context: AnalysisContext, *, max_hypotheses: int=500):
    if not 1<=max_hypotheses<=1000: raise ValueError("invalid tenant isolation report limit")
    grouped=defaultdict(dict)
    observations=[o for g in context.groups for o in g.observations]+context.ungrouped
    for item in observations:
        if item.kind!="url": continue
        try:
            parsed=urlsplit(item.value)
            if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: continue
            host=(item.host_key or parsed.hostname).lower().rstrip(".")
            parts=[p.lower() for p in parsed.path.split("/") if p]
            resource=next((RESOURCES[p] for p in parts if p in RESOURCES),None)
            if not resource: continue
            tenant_positions=[i for i,p in enumerate(parts) if p in TENANT_MARKERS]
            explicit=bool(tenant_positions)
            tenant_context="explicit_tenant_path" if explicit else "unscoped_resource"
            route="/" + "/".join(parts)
            grouped[(host,resource)][route]=TenantRouteEvidence(route_template=route,
                tenant_context=tenant_context,tenant_markers=sorted({parts[i] for i in tenant_positions}),
                object_reference_present=_object_ref(parts),observation_ids=sorted(set(item.observation_ids)))
        except ValueError: continue
    output=[]
    for (host,resource),routes in sorted(grouped.items()):
        evidence=[routes[k] for k in sorted(routes)]
        contexts={x.tenant_context for x in evidence}
        reasons=[]
        if "explicit_tenant_path" in contexts and "unscoped_resource" in contexts:
            reasons.append("tenant_and_unscoped_surfaces_coexist")
        tenant_names={m for x in evidence for m in x.tenant_markers}
        if len(tenant_names)>1: reasons.append("multiple_tenant_scopes_observed")
        if any(x.tenant_context=="explicit_tenant_path" and x.object_reference_present for x in evidence):
            reasons.append("tenant_object_reference_observed")
        if not reasons: continue
        refs=sorted({r for x in evidence for r in x.observation_ids})[:500]
        output.append(TenantIsolationHypothesis(host=host,resource=resource,route_evidence=evidence[:30],
            review_reasons=reasons,validation_questions=[
              "Does the server derive tenant identity from the authenticated session rather than trusting a client-supplied tenant ID?",
              "Can a user from tenant A read, modify, delete, or export tenant B records using an authorized test account?",
              "Are tenant filters applied to every list, search, detail, bulk, export, and background-job query?",
              "Are nested object references checked against both tenant membership and object ownership?",
              "Do caches, file storage keys, webhooks, and asynchronous jobs preserve tenant boundaries?",
              "Can changing organization, workspace, or account identifiers cause cross-tenant data exposure?",
            ],supporting_observation_ids=refs))
    output.sort(key=lambda x:(x.host,x.resource))
    if len(output)>max_hypotheses: raise ValueError("tenant isolation report limit exceeded")
    return TenantIsolationReport(hypotheses=output)

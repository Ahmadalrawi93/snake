"""Correlate passive operation routes to prioritize manual authorization review."""
from collections import defaultdict
from urllib.parse import urlsplit
from app.schemas.analysis_context import AnalysisContext
from app.schemas.cross_endpoint_authorization import CrossEndpointAuthorizationReport, CrossEndpointAuthorizationHypothesis, EndpointOperationEvidence

RESOURCES={"user":"users","users":"users","account":"accounts","accounts":"accounts","order":"orders","orders":"orders",
"payment":"payments","payments":"payments","invoice":"invoices","invoices":"invoices","subscription":"subscriptions","subscriptions":"subscriptions",
"document":"documents","documents":"documents","file":"files","files":"files","organization":"organizations","organizations":"organizations",
"project":"projects","projects":"projects","member":"members","members":"members","report":"reports","reports":"reports"}
ACTIONS={"create","new","add","update","edit","delete","remove","cancel","approve","reject","refund","transfer","pay","checkout","publish","invite","verify","reset","confirm"}
BULK={"bulk","batch","mass"}
EXPORT={"export","download","report"}
def _classify(parts):
    action=sorted(set(parts)&ACTIONS)
    if set(parts)&BULK: return "bulk",action
    if set(parts)&EXPORT: return "export",action
    if action: return "named_action",action
    if any(p in {"{id}",":id","{uuid}",":uuid"} or p.isdigit() or
           (len(p)>=16 and all(ch in "0123456789abcdef-" for ch in p)) for p in parts):
        return "object",[]
    return "collection",[]
def build_cross_endpoint_authorization_report(context:AnalysisContext,*,max_hypotheses:int=500):
    if not 1<=max_hypotheses<=1000: raise ValueError("invalid cross-endpoint report limit")
    grouped=defaultdict(dict)
    observations=[o for g in context.groups for o in g.observations]+context.ungrouped
    for item in observations:
        if item.kind!="url": continue
        try:
            parsed=urlsplit(item.value)
            if parsed.scheme not in {"http","https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: continue
            host=(item.host_key or parsed.hostname).lower().rstrip(".")
            parts=[p.lower() for p in parsed.path.split("/") if p]
            if not parts: continue
            resource=next((RESOURCES[p] for p in parts if p in RESOURCES),None)
            if not resource: continue
            kind,actions=_classify(parts)
            route="/" + "/".join(parts)
            grouped[(host,resource)][route]=EndpointOperationEvidence(route_template=route,
                operation_kind=kind,action_markers=actions,
                object_reference_present=(kind=="object"),
                observation_ids=sorted(set(item.observation_ids)))
        except ValueError: continue
    output=[]
    for (host,resource),routes in sorted(grouped.items()):
        ops=[routes[k] for k in sorted(routes)]
        kinds={x.operation_kind for x in ops}
        if len(kinds)<2: continue
        reasons=["operation_surfaces_coexist"]
        if {"collection","object"}<=kinds: reasons.append("object_and_collection_surfaces_coexist")
        if kinds & {"bulk","export"}: reasons.append("bulk_or_export_surface_observed")
        if sum(x.operation_kind=="named_action" for x in ops)>1: reasons.append("multiple_named_actions_observed")
        refs=sorted({ref for x in ops for ref in x.observation_ids})[:500]
        output.append(CrossEndpointAuthorizationHypothesis(host=host,resource=resource,
          operations=ops[:40],review_reasons=reasons,supporting_observation_ids=refs,
          validation_questions=[
            "Do collection, detail, update, and delete handlers apply the same server-side object ownership checks?",
            "Can one authorized test account access another test account's object by changing only its identifier?",
            "Do bulk actions validate authorization independently for every object in the submitted set?",
            "Do export and download handlers enforce the same tenant, role, and object-level restrictions as detail views?",
            "Are named state-changing operations protected against unauthorized roles, invalid states, and replay?",
            "Are alternate API versions and route aliases subject to equivalent authorization checks?",
            "Does the server reject unauthorized requests even when the UI hides the corresponding operation?",
          ]))
    output.sort(key=lambda x:(x.host,x.resource))
    if len(output)>max_hypotheses: raise ValueError("cross-endpoint hypothesis limit exceeded")
    return CrossEndpointAuthorizationReport(hypotheses=output)

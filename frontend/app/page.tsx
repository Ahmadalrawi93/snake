"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type User = { id: number; email: string; role: string };
type Project = { id: number; name: string; description: string; created_at: string };
type Target = { id: number; value: string; target_type: string; status: string };
type Authorization = { id: number; reference: string; starts_at: string | null; expires_at: string | null; status: string; notes: string };
type ScopeSnapshot = { id: number; target_id: number; authorization_id: number; sha256: string; status: string; created_at: string; expires_at: string | null; snapshot: { target?: string; hostname?: string; execution_enabled?: boolean } };
type PendingAuthorization = { id: number; project_id: number; reference: string; starts_at: string | null; expires_at: string | null; notes: string; created_at: string };
type AnalysisRun = { id: number; provider: string; model: string; source_observation_count: number; status: string; disposition: string; execution_enabled: false; created_at: string };
type FindingCandidate = { id: number; analysis_run_id: number; candidate_fingerprint: string; qualification: string; finding_status: string; evidence_bundle_sha256: string; execution_enabled: boolean; created_at: string };
type CandidateDetail = { id: number; analysis_run_id: number; project_id: number; candidate_fingerprint: string; qualification: { title: string; category: string; qualification: string; evidence_quality: string; impact_quality: string; blockers: string[] }; evidence_bundle: { strategy_id: string; reviewer_note: string; items: { evidence_id: string; evidence_type: string; relationship: string; statement: string; source_label: string; observation_ids: string[]; recorded_at: string }[] }; evidence_bundle_sha256: string; finding_status: string; execution_enabled: boolean; created_at: string };
type LifecycleEvent = { id: number; from_status: string; to_status: string; rationale: string; created_at: string };
type EvidenceArtifact = { id: number; filename: string; media_type: string; content_sha256: string; size_bytes: number; description: string; created_at: string };
type HumanDecision = { id: number; candidate_fingerprint: string; outcome: string; evidence_sha256: string | null; validation_method: string; notes: string; created_at: string };
type ImpactAssessmentRecord = { id: number; assessment_sha256: string; final_severity: "not_assessed"; cvss_vector: null; execution_enabled: false; assessment: { assessment_status: string; severity_suggestion: string; blockers: string[]; rationale: string[] }; created_at: string };
type CandidateSimilarity = { candidate_fingerprint: string; compared_fingerprint: string; disposition: "exact_duplicate" | "possible_duplicate" | "distinct"; category_match: boolean; category_family_match: boolean; title_similarity: number; evidence_similarity: number; shared_observation_count: number; shared_route_count: number; rationale: string[]; requires_human_review: true; auto_merge: false };
type ReportPreview = { report: { title: string; severity: "not_assessed"; cvss_vector: null; confirmation_status: string; execution_enabled: false; requires_human_edit_and_independent_validation: true }; markdown: string };

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export default function Home() {
  const [token, setToken] = useState("");
  const [user, setUser] = useState<User | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [authorizations, setAuthorizations] = useState<Authorization[]>([]);
  const [snapshots, setSnapshots] = useState<ScopeSnapshot[]>([]);
  const [snapshotValidity, setSnapshotValidity] = useState<Record<number, string>>({});
  const [analysisRuns, setAnalysisRuns] = useState<AnalysisRun[]>([]);
  const [selectedAnalysisRunId, setSelectedAnalysisRunId] = useState<number | null>(null);
  const [candidates, setCandidates] = useState<FindingCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<CandidateDetail | null>(null);
  const [lifecycleEvents, setLifecycleEvents] = useState<LifecycleEvent[]>([]);
  const [evidenceArtifacts, setEvidenceArtifacts] = useState<EvidenceArtifact[]>([]);
  const [humanDecisions, setHumanDecisions] = useState<HumanDecision[]>([]);
  const [impactAssessments, setImpactAssessments] = useState<ImpactAssessmentRecord[]>([]);
  const [decisionEvidenceSha, setDecisionEvidenceSha] = useState("");
  const [impactEvidenceId, setImpactEvidenceId] = useState("");
  const [impactDimension, setImpactDimension] = useState("confidentiality");
  const [impactLevel, setImpactLevel] = useState("moderate");
  const [impactVerification, setImpactVerification] = useState("observed");
  const [impactScope, setImpactScope] = useState("unknown");
  const [impactSensitivity, setImpactSensitivity] = useState("unknown");
  const [impactStatement, setImpactStatement] = useState("");
  const [reportPreview, setReportPreview] = useState<ReportPreview | null>(null);
  const [candidateSimilarities, setCandidateSimilarities] = useState<CandidateSimilarity[]>([]);
  const [decisionOutcome, setDecisionOutcome] = useState("inconclusive");
  const [decisionMethod, setDecisionMethod] = useState("manual_reproduction");
  const [decisionNotes, setDecisionNotes] = useState("");
  const [evidenceDescription, setEvidenceDescription] = useState("");
  const [pendingAuthorizations, setPendingAuthorizations] = useState<PendingAuthorization[]>([]);
  const [reviewNotes, setReviewNotes] = useState<Record<number, string>>({});
  const [reviewScopes, setReviewScopes] = useState<Record<number, string>>({});
  const [targetValue, setTargetValue] = useState("");
  const [targetType, setTargetType] = useState("domain");
  const [authReference, setAuthReference] = useState("");
  const [authStartsAt, setAuthStartsAt] = useState("");
  const [authExpiresAt, setAuthExpiresAt] = useState("");
  const [authNotes, setAuthNotes] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [projectName, setProjectName] = useState("");
  const [projectDescription, setProjectDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const api = useCallback(async (path: string, options: RequestInit = {}, accessToken = token) => {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...options.headers
      }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`;
      throw new Error(detail);
    }
    return body;
  }, [token]);

  const loadWorkspace = useCallback(async (accessToken: string) => {
    const [currentUser, projectList] = await Promise.all([
      api("/api/v1/auth/me", {}, accessToken),
      api("/api/v1/projects", {}, accessToken)
    ]);
    setUser(currentUser);
    setProjects(projectList);
    if (currentUser.role === "admin") {
      setPendingAuthorizations(await api("/api/v1/admin/authorizations/pending", {}, accessToken));
    } else {
      setPendingAuthorizations([]);
    }
  }, [api]);

  const loadProjectResources = useCallback(async (projectId: number) => {
    const [targetList, authorizationList, snapshotList, runList] = await Promise.all([
      api(`/api/v1/projects/${projectId}/targets`),
      api(`/api/v1/projects/${projectId}/authorizations`),
      api(`/api/v1/projects/${projectId}/scope-snapshots`),
      api(`/api/v1/projects/${projectId}/analysis-runs`)
    ]);
    setTargets(targetList);
    setAuthorizations(authorizationList);
    setSnapshots(snapshotList);
    setAnalysisRuns(runList);
    setSelectedAnalysisRunId(null);
    setCandidates([]);
  }, [api]);

  async function selectProject(projectId: number) {
    setSelectedProjectId(projectId);
    setTargets([]);
    setAuthorizations([]);
    setSnapshots([]);
    setSnapshotValidity({});
    setAnalysisRuns([]);
    setSelectedAnalysisRunId(null);
    setCandidates([]);
    setError("");
    try {
      await loadProjectResources(projectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load project records");
    }
  }

  async function loadCandidates(analysisRunId: number) {
    setSelectedAnalysisRunId(analysisRunId);
    setCandidates([]);
    setError("");
    try {
      const rows = await api(`/api/v1/analysis-runs/${analysisRunId}/finding-candidates`);
      setCandidates(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load finding candidates");
    }
  }

  async function openCandidate(candidateId: number) {
    setBusy(true); setError(""); setSelectedCandidate(null); setReportPreview(null);
    try {
      const detail = await api(`/api/v1/finding-candidates/${candidateId}`);
      const [lifecycle, artifacts, impacts] = await Promise.all([
        api(`/api/v1/finding-candidates/${candidateId}/lifecycle`),
        api(`/api/v1/finding-candidates/${candidateId}/evidence`),
        api(`/api/v1/finding-candidates/${candidateId}/impact-assessments`)
      ]);
      let similarities: CandidateSimilarity[] = [];
      try {
        similarities = await api(`/api/v1/projects/${detail.project_id}/finding-candidates/${candidateId}/similarity`);
      } catch {
        setError("Candidate details loaded, but duplicate comparison was withheld because one or more project records failed integrity checks.");
      }
      const decisions = await api(`/api/v1/analysis-runs/${detail.analysis_run_id}/finding-decisions?candidate_fingerprint=${detail.candidate_fingerprint}`);
      setSelectedCandidate(detail);
      setLifecycleEvents(lifecycle.events || []);
      setEvidenceArtifacts(artifacts);
      setImpactAssessments(impacts);
      setCandidateSimilarities(similarities);
      setDecisionEvidenceSha(artifacts[0]?.content_sha256 || "");
      setImpactEvidenceId(detail.evidence_bundle.items.find((item: { evidence_type: string }) => item.evidence_type === "impact_context")?.evidence_id || "");
      setHumanDecisions(decisions);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load candidate detail");
    } finally {
      setBusy(false);
    }
  }

  async function uploadCandidateEvidence(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedCandidate) return;
    const form = event.currentTarget;
    const fileInput = form.elements.namedItem("evidenceFile") as HTMLInputElement | null;
    const file = fileInput?.files?.[0];
    if (!file) { setError("Choose an evidence file first."); return; }
    if (file.size < 1 || file.size > 1024 * 1024) { setError("Evidence file must be between 1 byte and 1 MiB."); return; }
    const allowed = ["text/plain", "application/json", "image/png", "image/jpeg", "application/pdf", "application/octet-stream"];
    const mediaType = allowed.includes(file.type) ? file.type : "application/octet-stream";
    setBusy(true); setError(""); setMessage("");
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("Could not read evidence file"));
        reader.onerror = () => reject(new Error("Could not read evidence file"));
        reader.readAsDataURL(file);
      });
      const contentBase64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
      await api(`/api/v1/finding-candidates/${selectedCandidate.id}/evidence`, {
        method: "POST",
        body: JSON.stringify({ filename: file.name, media_type: mediaType, content_base64: contentBase64, description: evidenceDescription })
      });
      setEvidenceDescription("");
      form.reset();
      const rows = await api(`/api/v1/finding-candidates/${selectedCandidate.id}/evidence`);
      setEvidenceArtifacts(rows);
      setMessage("Evidence encrypted and stored. Its SHA-256 digest is now available for a human decision.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Evidence upload failed");
    } finally {
      setBusy(false);
    }
  }

  async function recordCandidateDecision(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedCandidate) return;
    const evidenceRequired = decisionOutcome === "confirmed" || decisionOutcome === "false_positive";
    if (evidenceRequired && !evidenceArtifacts.some(item => item.content_sha256)) {
      setError("Upload evidence before recording this decision.");
      return;
    }
    setBusy(true); setError(""); setMessage("");
    try {
      const payload: Record<string, unknown> = {
        candidate_fingerprint: selectedCandidate.candidate_fingerprint,
        outcome: decisionOutcome,
        validation_method: decisionMethod,
        notes: decisionNotes,
        reviewer_attested: true
      };
      if (evidenceRequired) {
        if (!decisionEvidenceSha || !evidenceArtifacts.some(item => item.content_sha256 === decisionEvidenceSha)) throw new Error("Select an evidence artifact from the encrypted vault.");
        payload.evidence_sha256 = decisionEvidenceSha;
      }
      await api(`/api/v1/analysis-runs/${selectedCandidate.analysis_run_id}/finding-decisions`, {
        method: "POST", body: JSON.stringify(payload)
      });
      setDecisionNotes("");
      const decisions = await api(`/api/v1/analysis-runs/${selectedCandidate.analysis_run_id}/finding-decisions?candidate_fingerprint=${selectedCandidate.candidate_fingerprint}`);
      setHumanDecisions(decisions);
      setMessage("Human review decision recorded in the append-only review log.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record human decision");
    } finally {
      setBusy(false);
    }
  }

  async function recordImpactAssessment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedCandidate) return;
    const evidence = selectedCandidate.evidence_bundle.items.find(item => item.evidence_id === impactEvidenceId && item.evidence_type === "impact_context");
    if (!evidence || evidence.observation_ids.length === 0) {
      setError("Select an impact-context evidence record with linked observations.");
      return;
    }
    if (impactStatement.trim().length < 8) { setError("Impact statement must contain at least 8 characters."); return; }
    setBusy(true); setError(""); setMessage("");
    try {
      await api(`/api/v1/finding-candidates/${selectedCandidate.id}/impact-assessments`, {
        method: "POST",
        body: JSON.stringify({
          claims: [{
            evidence_id: evidence.evidence_id,
            observation_ids: evidence.observation_ids,
            dimension: impactDimension,
            level: impactLevel,
            verification: impactVerification,
            scope: impactScope,
            data_sensitivity: impactSensitivity,
            statement: impactStatement.trim(),
            human_attested: true
          }]
        })
      });
      setImpactStatement("");
      const rows = await api(`/api/v1/finding-candidates/${selectedCandidate.id}/impact-assessments`);
      setImpactAssessments(rows);
      setMessage("Impact annotation saved. Final severity remains not assessed and requires independent validation.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Impact assessment could not be saved");
    } finally {
      setBusy(false);
    }
  }

  async function generateCandidateReport() {
    if (!selectedCandidate) return;
    setBusy(true); setError(""); setMessage(""); setReportPreview(null);
    try {
      const result = await api(`/api/v1/finding-candidates/${selectedCandidate.id}/report-draft`, { method: "POST" });
      setReportPreview(result);
      setMessage("Report draft generated from verified persisted evidence. It has not been submitted or independently validated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report draft requirements are not satisfied");
    } finally {
      setBusy(false);
    }
  }

  async function transitionCandidate(newStatus: string, rationale: string) {
    if (!selectedCandidate) return;
    const currentStatus = lifecycleEvents.length ? lifecycleEvents[lifecycleEvents.length - 1].to_status : "new";
    setBusy(true); setError(""); setMessage("");
    try {
      await api(`/api/v1/finding-candidates/${selectedCandidate.id}/lifecycle`, {
        method: "POST",
        body: JSON.stringify({ expected_status: currentStatus, new_status: newStatus, rationale })
      });
      const lifecycle = await api(`/api/v1/finding-candidates/${selectedCandidate.id}/lifecycle`);
      setLifecycleEvents(lifecycle.events || []);
      setMessage(`Candidate lifecycle updated: ${currentStatus} → ${newStatus}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Lifecycle transition rejected");
    } finally {
      setBusy(false);
    }
  }

  async function reviewAuthorization(authorizationId: number, decision: "approved" | "rejected") {
    const notes = (reviewNotes[authorizationId] || "").trim();
    const scopeRules = (reviewScopes[authorizationId] || "").split(",").map(rule => rule.trim()).filter(Boolean);
    if (notes.length < 3) {
      setError("Review notes must contain at least 3 characters.");
      return;
    }
    if (decision === "approved" && scopeRules.length === 0) {
      setError("Approval requires explicit hostname scope rules.");
      return;
    }
    setBusy(true); setError(""); setMessage("");
    try {
      await api(`/api/v1/admin/authorizations/${authorizationId}/review`, {
        method: "POST",
        body: JSON.stringify({ decision, review_notes: notes, scope_rules: decision === "approved" ? scopeRules : [] })
      });
      setPendingAuthorizations(current => current.filter(item => item.id !== authorizationId));
      setMessage(`Authorization #${authorizationId} ${decision}. The owner can now request a scope snapshot if the approved rules cover a target.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authorization review failed");
    } finally {
      setBusy(false);
    }
  }

  async function createScopeSnapshot(targetId: number) {
    if (!selectedProjectId) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const created = await api(`/api/v1/projects/${selectedProjectId}/targets/${targetId}/scope-snapshots`, {
        method: "POST"
      });
      setSnapshots(current => [created, ...current]);
      setMessage(`Scope snapshot #${created.id} created. Execution remains disabled.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scope snapshot could not be created");
    } finally {
      setBusy(false);
    }
  }

  async function validateScopeSnapshot(snapshotId: number) {
    setBusy(true); setError("");
    try {
      const result = await api(`/api/v1/scope-snapshots/${snapshotId}/validate`);
      setSnapshotValidity(current => ({
        ...current,
        [snapshotId]: result.valid ? "VALID" : `INVALID: ${result.reasons.join(", ")}`
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Snapshot validation failed");
    } finally {
      setBusy(false);
    }
  }

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedProjectId || !targetValue.trim()) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const created = await api(`/api/v1/projects/${selectedProjectId}/targets`, {
        method: "POST",
        body: JSON.stringify({ value: targetValue.trim(), target_type: targetType })
      });
      setTargets(current => [created, ...current]);
      setTargetValue("");
      setMessage("Target stored. No DNS lookup, HTTP request, or scan was performed.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not register target");
    } finally {
      setBusy(false);
    }
  }

  async function createAuthorization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedProjectId || !authReference.trim()) return;
    if (authStartsAt && authExpiresAt && authExpiresAt < authStartsAt) {
      setError("Expiry date cannot be earlier than the authorization start date.");
      return;
    }
    setBusy(true); setError(""); setMessage("");
    try {
      const created = await api(`/api/v1/projects/${selectedProjectId}/authorizations`, {
        method: "POST",
        body: JSON.stringify({
          reference: authReference.trim(),
          starts_at: authStartsAt || null,
          expires_at: authExpiresAt || null,
          notes: authNotes.trim()
        })
      });
      setAuthorizations(current => [created, ...current]);
      setAuthReference(""); setAuthStartsAt(""); setAuthExpiresAt(""); setAuthNotes("");
      setMessage("Authorization reference recorded as PENDING. This does not authorize scanning.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record authorization");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const saved = window.localStorage.getItem("snake_access_token");
    if (!saved) return;
    setToken(saved);
    loadWorkspace(saved).catch(() => {
      window.localStorage.removeItem("snake_access_token");
      setToken("");
      setUser(null);
      setProjects([]);
    });
  }, [loadWorkspace]);

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    try {
      if (authMode === "register") {
        await api("/api/v1/auth/register", {
          method: "POST", body: JSON.stringify({ email, password })
        }, "");
      }
      const result = await api("/api/v1/auth/login", {
        method: "POST", body: JSON.stringify({ email, password })
      }, "");
      window.localStorage.setItem("snake_access_token", result.access_token);
      setToken(result.access_token);
      await loadWorkspace(result.access_token);
      setPassword("");
      setMessage(authMode === "register" ? "Account created. Workspace ready." : "Signed in successfully.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectName.trim()) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const created = await api("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify({ name: projectName.trim(), description: projectDescription.trim() })
      });
      setProjects(current => [created, ...current]);
      setProjectName(""); setProjectDescription("");
      setSelectedProjectId(created.id);
      setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({}); setAnalysisRuns([]); setSelectedAnalysisRunId(null); setCandidates([]);
      setMessage("Project created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    window.localStorage.removeItem("snake_access_token");
    setToken(""); setUser(null); setProjects([]); setSelectedProjectId(null); setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({}); setAnalysisRuns([]); setSelectedAnalysisRunId(null); setCandidates([]); setPendingAuthorizations([]); setReviewNotes({}); setReviewScopes({}); setMessage(""); setError("");
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">S</span><div><b>SNAKE</b><small>SECURITY OPERATIONS</small></div></div>
        <div className="nav-label">WORKSPACE</div>
        <div className="nav-item active"><span>◈</span>Overview</div>
        <div className="nav-item disabled"><span>⌘</span>AI Analysis <small>NOT CONNECTED</small></div>
        <div className="nav-item disabled"><span>◎</span>Targets</div>
        <div className="nav-item disabled"><span>⌁</span>Scan Jobs</div>
        <div className="nav-item disabled"><span>◇</span>Findings</div>
        <div className="nav-item disabled"><span>▤</span>Intelligence</div>
        <div className="sidebar-bottom"><span className="status-dot">●</span> CONTROL PLANE ONLINE <small>v0.3.0</small></div>
      </aside>

      <section className="content">
        <header>
          <div><p className="eyebrow">SECURITY WORKSPACE / OVERVIEW</p><h1>Command Center</h1><p className="muted">A controlled environment for authorized security research.</p></div>
          {user ? <div className="profile">{user.email} <button className="text-button" onClick={signOut}>SIGN OUT</button></div> : <div className="profile">LOCAL INSTANCE <span>●</span></div>}
        </header>

        <div className="notice"><b>FOUNDATION MODE</b><span>Account, project, authorization-reference, and target registration are active. No scanning or target network requests are initiated from this dashboard.</span></div>

        {error && <div className="feedback error" role="alert">{error}</div>}
        {message && <div className="feedback success" role="status">{message}</div>}

        {!user ? (
          <section className="auth-panel">
            <div className="section-heading"><div><p className="eyebrow">IDENTITY & ACCESS</p><h2>{authMode === "login" ? "Sign in to SNAKE" : "Create your account"}</h2></div></div>
            <form onSubmit={submitAuth} className="stack-form">
              <label>Email address<input type="email" autoComplete="email" required maxLength={320} value={email} onChange={e => setEmail(e.target.value)} placeholder="researcher@example.com" /></label>
              <label>Password<input type="password" autoComplete={authMode === "login" ? "current-password" : "new-password"} required minLength={authMode === "register" ? 12 : 1} maxLength={128} value={password} onChange={e => setPassword(e.target.value)} placeholder={authMode === "register" ? "At least 12 characters" : "Your password"} /></label>
              <button className="primary-button" disabled={busy}>{busy ? "PLEASE WAIT..." : authMode === "login" ? "SIGN IN" : "CREATE ACCOUNT"}</button>
            </form>
            <p className="switch-auth">{authMode === "login" ? "New to SNAKE?" : "Already registered?"} <button className="text-button" onClick={() => { setAuthMode(authMode === "login" ? "register" : "login"); setError(""); }}>{authMode === "login" ? "Create an account" : "Sign in"}</button></p>
            <p className="hint">Registration creates a standard user account. Administrator privileges are never granted by public registration.</p>
          </section>
        ) : (
          <>
            <div className="metrics">
              <article><small>YOUR PROJECTS</small><strong>{projects.length}</strong><span>Owner-scoped workspace</span></article>
              <article><small>RUNNING SCANS</small><strong>0</strong><span>Execution is disabled</span></article>
              <article><small>OPEN FINDINGS</small><strong>0</strong><span>Not loaded in dashboard yet</span></article>
              <article><small>ACCOUNT ROLE</small><strong className="pending">{user.role.toUpperCase()}</strong><span>Authenticated session</span></article>
            </div>

            {user.role === "admin" && (
              <section className="admin-review">
                <div className="section-heading"><div><p className="eyebrow">ADMINISTRATION</p><h2>Authorization review queue</h2></div><span className="muted">{pendingAuthorizations.length} PENDING</span></div>
                {pendingAuthorizations.length === 0 ? <div className="empty-state admin-empty">No pending authorization records.</div> : pendingAuthorizations.map(item => (
                  <article className="review-card" key={item.id}>
                    <div className="review-meta"><b>Authorization #{item.id} · Project #{item.project_id}</b><small>{item.starts_at || "Start unspecified"} → {item.expires_at || "Expiry unspecified"}</small></div>
                    <p className="reference">{item.reference}</p>
                    <p>{item.notes || "No submitter notes."}</p>
                    <label>Review notes<input value={reviewNotes[item.id] || ""} onChange={e => setReviewNotes(current => ({ ...current, [item.id]: e.target.value }))} placeholder="What did you verify?" maxLength={4000} /></label>
                    <label>Approved hostname rules (comma-separated)<input value={reviewScopes[item.id] || ""} onChange={e => setReviewScopes(current => ({ ...current, [item.id]: e.target.value }))} placeholder="example.com, *.example.com" /></label>
                    <div className="review-actions"><button className="primary-button" disabled={busy} onClick={() => reviewAuthorization(item.id, "approved")}>APPROVE WITH SCOPE</button><button className="danger-button" disabled={busy} onClick={() => reviewAuthorization(item.id, "rejected")}>REJECT</button></div>
                  </article>
                ))}
                <p className="hint">Approval is an administrative decision. Enter only hostnames actually covered by independently verified program permission. Never approve a wildcard unless the program explicitly authorizes it.</p>
              </section>
            )}

            <div className="section-heading"><div><p className="eyebrow">PROJECT MANAGEMENT</p><h2>Your projects</h2></div><span className="muted">{projects.length} RECORDS</span></div>
            <section className="project-layout">
              <form onSubmit={createProject} className="project-form">
                <h3>New project</h3>
                <label>Project name<input required minLength={2} maxLength={120} value={projectName} onChange={e => setProjectName(e.target.value)} placeholder="e.g. Authorized BBP research" /></label>
                <label>Description<textarea maxLength={4000} rows={4} value={projectDescription} onChange={e => setProjectDescription(e.target.value)} placeholder="Purpose, program reference, and internal notes" /></label>
                <button className="primary-button" disabled={busy || projectName.trim().length < 2}>{busy ? "SAVING..." : "CREATE PROJECT"}</button>
              </form>
              <div className="project-list">
                {projects.length === 0 ? <div className="empty-state"><b>No projects yet</b><span>Create a project to start organizing authorization records and targets.</span></div> :
                  projects.map(project => <article className={selectedProjectId === project.id ? "project-card selected" : "project-card"} key={project.id}><div><small>PROJECT #{project.id}</small><h3>{project.name}</h3><p>{project.description || "No description provided."}</p></div><div className="project-actions"><time>{new Date(project.created_at).toLocaleDateString()}</time><button className="text-button" onClick={() => selectProject(project.id)}>OPEN WORKSPACE →</button></div></article>)}
              </div>
            </section>

            {selectedProjectId !== null && (
              <section className="project-detail">
                <div className="section-heading"><div><p className="eyebrow">PROJECT #{selectedProjectId}</p><h2>Scope & authorization records</h2></div><button className="text-button" onClick={() => { setSelectedProjectId(null); setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({}); setAnalysisRuns([]); setSelectedAnalysisRunId(null); setCandidates([]); }}>CLOSE WORKSPACE</button></div>
                <div className="project-layout">
                  <form onSubmit={createAuthorization} className="project-form">
                    <h3>Record authorization reference</h3>
                    <label>Program / permission URL<input required minLength={3} maxLength={500} value={authReference} onChange={e => setAuthReference(e.target.value)} placeholder="https://bugcrowd.com/program/..." /></label>
                    <label>Start date (optional)<input type="date" value={authStartsAt} onChange={e => setAuthStartsAt(e.target.value)} /></label>
                    <label>Expiry date (optional)<input type="date" value={authExpiresAt} onChange={e => setAuthExpiresAt(e.target.value)} /></label>
                    <label>Notes<textarea rows={3} maxLength={4000} value={authNotes} onChange={e => setAuthNotes(e.target.value)} placeholder="Scope notes and permission details" /></label>
                    <button className="primary-button" disabled={busy || authReference.trim().length < 3}>SAVE AS PENDING</button>
                    <p className="hint">A saved reference is not proof of authorization and does not enable testing. Approval and scope validation remain separate controls.</p>
                  </form>
                  <form onSubmit={createTarget} className="project-form">
                    <h3>Register target</h3>
                    <label>Target value<input required maxLength={2048} value={targetValue} onChange={e => setTargetValue(e.target.value)} placeholder="example.com or https://example.com" /></label>
                    <label>Target type<select value={targetType} onChange={e => setTargetType(e.target.value)}><option value="domain">Domain</option><option value="url">URL</option><option value="ip">IP address</option><option value="cidr">CIDR</option></select></label>
                    <button className="primary-button" disabled={busy || !targetValue.trim()}>STORE TARGET</button>
                    <p className="hint">Registration is storage only. SNAKE will not resolve, connect to, or scan this target.</p>
                  </form>
                </div>
                <div className="records-grid">
                  <div className="record-panel"><h3>Registered targets <span>{targets.length}</span></h3>{targets.length === 0 ? <p className="muted">No targets registered.</p> : targets.map(target => <div className="record-row" key={target.id}><div><b>{target.value}</b><small>{target.target_type.toUpperCase()} · {target.status.toUpperCase()}</small>{(target.target_type === "url" || target.target_type === "domain") ? <button className="text-button" disabled={busy} onClick={() => createScopeSnapshot(target.id)}>CREATE SCOPE SNAPSHOT</button> : <small>SNAPSHOT SUPPORT: URL / DOMAIN ONLY</small>}</div><time>#{target.id}</time></div>)}</div>
                  <div className="record-panel"><h3>Authorization references <span>{authorizations.length}</span></h3>{authorizations.length === 0 ? <p className="muted">No authorization records.</p> : authorizations.map(record => <div className="record-row" key={record.id}><div><b>{record.reference}</b><small>{record.status.toUpperCase()} · {record.starts_at || "Start unspecified"} → {record.expires_at || "Expiry unspecified"}</small>{record.notes && <p>{record.notes}</p>}</div><time>#{record.id}</time></div>)}</div>
                </div>
                <div className="records-grid">
                  <div className="record-panel snapshot-panel"><h3>Immutable scope snapshots <span>{snapshots.length}</span></h3>{snapshots.length === 0 ? <p className="muted">No scope snapshots. A currently valid, approved authorization must cover a target.</p> : snapshots.map(snapshot => <div className="record-row" key={snapshot.id}><div><b>Snapshot #{snapshot.id} · {snapshot.snapshot.hostname || "Target scope"}</b><small>{snapshot.status.toUpperCase()} · SHA-256 {snapshot.sha256.slice(0, 16)}… · EXECUTION DISABLED</small>{snapshotValidity[snapshot.id] && <small>{snapshotValidity[snapshot.id]}</small>}<button className="text-button" disabled={busy} onClick={() => validateScopeSnapshot(snapshot.id)}>VALIDATE SNAPSHOT</button></div><time>TARGET #{snapshot.target_id}</time></div>)}</div>
                </div>
                <div className="records-grid">
                  <div className="record-panel analysis-panel">
                    <h3>AI analysis history <span>{analysisRuns.length}</span></h3>
                    {analysisRuns.length === 0 ? <p className="muted">No persisted AI analysis runs for this project.</p> : analysisRuns.map(run => (
                      <div className="record-row" key={run.id}>
                        <div><b>Analysis #{run.id} · {run.provider} / {run.model}</b><small>{run.source_observation_count} source observations · {run.disposition.replaceAll("_", " ").toUpperCase()} · EXECUTION DISABLED</small><button className="text-button" disabled={busy} onClick={() => loadCandidates(run.id)}>VIEW FINDING CANDIDATES</button></div>
                        <time>{new Date(run.created_at).toLocaleDateString()}</time>
                      </div>
                    ))}
                  </div>
                </div>
                {selectedAnalysisRunId !== null && (
                  <div className="record-panel candidate-panel">
                    <h3>Finding candidates from analysis #{selectedAnalysisRunId} <span>{candidates.length}</span></h3>
                    {candidates.length === 0 ? <p className="muted">No persisted candidates in this analysis run.</p> : candidates.map(candidate => (
                      <div className="record-row" key={candidate.id}>
                        <div><b>Candidate #{candidate.id} · {candidate.qualification.replaceAll("_", " ").toUpperCase()}</b><small>{candidate.finding_status.toUpperCase()} · FINGERPRINT {candidate.candidate_fingerprint.slice(0, 16)}… · EXECUTION DISABLED</small><small>EVIDENCE SHA-256 {candidate.evidence_bundle_sha256.slice(0, 16)}…</small><button className="text-button" disabled={busy} onClick={() => openCandidate(candidate.id)}>OPEN REVIEW WORKSPACE</button></div>
                        <time>{new Date(candidate.created_at).toLocaleDateString()}</time>
                      </div>
                    ))}
                  </div>
                )}
                {selectedCandidate && (
                  <div className="candidate-review-workspace">
                    <div className="section-heading"><div><p className="eyebrow">HUMAN REVIEW</p><h2>{selectedCandidate.qualification.title}</h2><p className="muted">Candidate #{selectedCandidate.id} · {selectedCandidate.qualification.category}</p></div><button className="text-button" onClick={() => setSelectedCandidate(null)}>CLOSE REVIEW</button></div>
                    <div className="review-facts">
                      <span>STATUS: {lifecycleEvents.length ? lifecycleEvents[lifecycleEvents.length - 1].to_status.toUpperCase() : "NEW"}</span>
                      <span>QUALIFICATION: {selectedCandidate.qualification.qualification.toUpperCase()}</span>
                      <span>EXECUTION: DISABLED</span>
                    </div>
                    {selectedCandidate.qualification.blockers.length > 0 && <div className="review-card"><b>Qualification blockers</b><ul>{selectedCandidate.qualification.blockers.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                    <div className="review-card"><h3>Evidence bundle · {selectedCandidate.evidence_bundle.items.length} records</h3>{selectedCandidate.evidence_bundle.items.map(item => <div className="record-row" key={item.evidence_id}><div><b>{item.evidence_type.replaceAll("_", " ").toUpperCase()} · {item.relationship.toUpperCase()}</b><p>{item.statement}</p><small>{item.source_label} · {item.observation_ids.length} observation links</small><small>Evidence ID: {item.evidence_id}</small></div></div>)}<small>Bundle SHA-256: {selectedCandidate.evidence_bundle_sha256}</small></div>
                    <div className="records-grid">
                      <form className="review-card" onSubmit={uploadCandidateEvidence}>
                        <h3>Encrypted evidence vault</h3>
                        <label>Evidence file (max 1 MiB)<input name="evidenceFile" type="file" required /></label>
                        <label>Description<input value={evidenceDescription} onChange={e => setEvidenceDescription(e.target.value)} maxLength={1000} /></label>
                        <button className="primary-button" disabled={busy}>ENCRYPT & STORE EVIDENCE</button>
                        {evidenceArtifacts.map(item => <div className="record-row" key={item.id}><div><b>{item.filename}</b><small>{item.size_bytes} bytes · {item.media_type}</small><small>SHA-256: {item.content_sha256}</small></div><time>#{item.id}</time></div>)}
                      </form>
                      <section className="review-card">
                        <h3>Human decision log</h3>
                        {humanDecisions.map(item => <div className="record-row" key={item.id}><div><b>{item.outcome.toUpperCase()}</b><small>{item.validation_method} · {item.created_at}</small><small>{item.evidence_sha256 || "No evidence digest"}</small></div><time>#{item.id}</time></div>)}
                        {humanDecisions.length > 0 ? <p className="hint">A reviewer can record only one immutable decision for this candidate. This account has already submitted its decision; the API will reject a second one.</p> : (
                      <form onSubmit={recordCandidateDecision}>
                        <label>Outcome<select value={decisionOutcome} onChange={e => setDecisionOutcome(e.target.value)}><option value="inconclusive">Inconclusive</option><option value="confirmed">Confirmed</option><option value="false_positive">False positive</option><option value="duplicate">Duplicate</option></select></label>
                        <label>Validation method<input value={decisionMethod} onChange={e => setDecisionMethod(e.target.value)} required minLength={3} maxLength={80} pattern="[a-z][a-z0-9_]{2,79}" /></label>
                        <label>Review notes<textarea value={decisionNotes} onChange={e => setDecisionNotes(e.target.value)} rows={3} maxLength={2000} /></label>
                        {(decisionOutcome === "confirmed" || decisionOutcome === "false_positive") && <><label>Evidence artifact<select required value={decisionEvidenceSha} onChange={e => setDecisionEvidenceSha(e.target.value)}><option value="">Select evidence</option>{evidenceArtifacts.map(item => <option key={item.id} value={item.content_sha256}>{item.filename} · {item.content_sha256.slice(0, 12)}…</option>)}</select></label><p className="hint">The decision will bind to the selected encrypted-vault artifact digest.</p></>}
                        <button className="primary-button" disabled={busy}>RECORD HUMAN DECISION</button>
                      </form>
                        )}
                      </section>
                    </div>
                    <form className="review-card" onSubmit={recordImpactAssessment}>
                      <h3>Evidence-bound impact annotation</h3>
                      <p className="hint">Only impact-context evidence with linked source observations can support a claim. This is a human annotation, not a final severity decision.</p>
                      <label>Impact evidence<select required value={impactEvidenceId} onChange={e => setImpactEvidenceId(e.target.value)}><option value="">Select impact-context evidence</option>{selectedCandidate.evidence_bundle.items.filter(item => item.evidence_type === "impact_context").map(item => <option key={item.evidence_id} value={item.evidence_id}>{item.source_label} · {item.observation_ids.length} observations</option>)}</select></label>
                      <label>Dimension<select value={impactDimension} onChange={e => setImpactDimension(e.target.value)}>{["confidentiality","integrity","availability","authentication","authorization","privilege_escalation","financial","privacy","operational"].map(item => <option key={item} value={item}>{item}</option>)}</select></label>
                      <label>Impact level<select value={impactLevel} onChange={e => setImpactLevel(e.target.value)}><option value="none">None</option><option value="low">Low</option><option value="moderate">Moderate</option><option value="high">High</option></select></label>
                      <label>Verification<select value={impactVerification} onChange={e => setImpactVerification(e.target.value)}><option value="observed">Directly observed</option><option value="potential">Potential only</option></select></label>
                      <label>Impact scope<select value={impactScope} onChange={e => setImpactScope(e.target.value)}><option value="single_test_record">Single test record</option><option value="multiple_records">Multiple records</option><option value="tenant_wide">Tenant-wide</option><option value="service_wide">Service-wide</option><option value="unknown">Unknown</option></select></label>
                      <label>Data sensitivity<select value={impactSensitivity} onChange={e => setImpactSensitivity(e.target.value)}><option value="synthetic_test_data">Synthetic test data</option><option value="low_sensitivity">Low sensitivity</option><option value="sensitive_data">Sensitive data</option><option value="critical_system">Critical system</option><option value="unknown">Unknown</option></select></label>
                      <label>What was observed or hypothesized?<textarea required minLength={8} maxLength={1200} rows={3} value={impactStatement} onChange={e => setImpactStatement(e.target.value)} /></label>
                      <button className="primary-button" disabled={busy || !impactEvidenceId || impactStatement.trim().length < 8}>SAVE IMPACT ANNOTATION</button>
                      {impactAssessments.map(item => <div className="record-row" key={item.id}><div><b>{item.assessment.assessment_status.replaceAll("_", " ").toUpperCase()}</b><small>Suggested: {item.assessment.severity_suggestion.toUpperCase()} · Final: NOT ASSESSED · CVSS: NONE</small><small>{item.assessment.rationale.join(" · ")}</small><small>SHA-256 {item.assessment_sha256.slice(0, 16)}…</small></div><time>#{item.id}</time></div>)}
                    </form>
                    <div className="review-card similarity-panel">
                      <h3>Project duplicate intelligence</h3>
                      <p className="hint">Similarity is a review aid, not proof of duplication. No candidate is merged or changed automatically.</p>
                      {candidateSimilarities.length === 0 ? <p className="hint">No other persisted candidates were found in this project.</p> : candidateSimilarities.map(item => <div className="record-row" key={item.compared_fingerprint}><div><b>{item.disposition.replaceAll("_", " ").toUpperCase()}</b><small>Candidate {item.compared_fingerprint.slice(0, 16)}…</small><small>Title similarity {(item.title_similarity * 100).toFixed(0)}% · Evidence similarity {(item.evidence_similarity * 100).toFixed(0)}%</small><small>Shared observations: {item.shared_observation_count} · Shared routes: {item.shared_route_count}</small><small>{item.rationale.join(" · ")}</small></div><time>{item.category_match ? "CATEGORY MATCH" : "CATEGORY DIFF"}</time></div>)}
                    </div>
                    <div className="review-card report-draft-panel">
                      <div className="review-meta"><h3>Evidence-bound report draft</h3><button className="primary-button" disabled={busy} onClick={generateCandidateReport}>GENERATE REPORT DRAFT</button></div>
                      <p className="hint">Requires consistent, complete evidence including observed behavior, expected behavior, and impact context. Generation does not submit the report.</p>
                      {reportPreview && <><div className="review-facts"><span>STATUS: UNCONFIRMED DRAFT</span><span>SEVERITY: NOT ASSESSED</span><span>CVSS: NONE</span><span>EXECUTION: DISABLED</span></div><button className="text-button" onClick={() => navigator.clipboard.writeText(reportPreview.markdown)}>COPY MARKDOWN</button><pre className="report-markdown">{reportPreview.markdown}</pre></>}
                    </div>
                    <div className="review-card">
                      <h3>Append-only lifecycle</h3>
                      <div className="review-actions">
                        {(!lifecycleEvents.length || lifecycleEvents[lifecycleEvents.length - 1].to_status === "new") && <button className="primary-button" disabled={busy} onClick={() => transitionCandidate("under_review", "Human review started.")}>START REVIEW</button>}
                        {lifecycleEvents.length > 0 && lifecycleEvents[lifecycleEvents.length - 1].to_status === "under_review" && <button className="primary-button" disabled={busy} onClick={() => transitionCandidate("needs_more_evidence", "Additional evidence is required.")}>REQUEST MORE EVIDENCE</button>}
                        {lifecycleEvents.length > 0 && lifecycleEvents[lifecycleEvents.length - 1].to_status === "under_review" && humanDecisions.some(item => item.outcome === "confirmed" && item.evidence_sha256 && evidenceArtifacts.some(artifact => artifact.content_sha256 === item.evidence_sha256)) && <button className="primary-button" disabled={busy} onClick={() => transitionCandidate("confirmed", "Human reviewer confirmed the candidate with encrypted evidence.")}>CONFIRM FINDING</button>}
                        {lifecycleEvents.length > 0 && lifecycleEvents[lifecycleEvents.length - 1].to_status === "under_review" && humanDecisions.some(item => item.outcome === "false_positive") && <button className="danger-button" disabled={busy} onClick={() => transitionCandidate("rejected", "Human reviewer rejected the candidate as a false positive.")}>REJECT AS FALSE POSITIVE</button>}
                        {lifecycleEvents.length > 0 && lifecycleEvents[lifecycleEvents.length - 1].to_status === "needs_more_evidence" && <button className="primary-button" disabled={busy} onClick={() => transitionCandidate("under_review", "Additional evidence review resumed.")}>RESUME REVIEW</button>}
                      </div>
                      {lifecycleEvents.map(item => <div className="record-row" key={item.id}><div><b>{item.from_status.toUpperCase()} → {item.to_status.toUpperCase()}</b><p>{item.rationale}</p></div><time>{new Date(item.created_at).toLocaleString()}</time></div>)}
                    </div>
                  </div>
                )}
              </section>
            )}
          </>
        )}

        <footer>SNAKE SECURITY PLATFORM <span>BUILT FOR AUTHORIZED TESTING ONLY</span></footer>
      </section>
    </main>
  );
}

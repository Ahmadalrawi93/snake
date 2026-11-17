"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type User = { id: number; email: string; role: string };
type Project = { id: number; name: string; description: string; created_at: string };
type Target = { id: number; value: string; target_type: string; status: string };
type Authorization = { id: number; reference: string; starts_at: string | null; expires_at: string | null; status: string; notes: string };
type ScopeSnapshot = { id: number; target_id: number; authorization_id: number; sha256: string; status: string; created_at: string; expires_at: string | null; snapshot: { target?: string; hostname?: string; execution_enabled?: boolean } };

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
  }, [api]);

  const loadProjectResources = useCallback(async (projectId: number) => {
    const [targetList, authorizationList, snapshotList] = await Promise.all([
      api(`/api/v1/projects/${projectId}/targets`),
      api(`/api/v1/projects/${projectId}/authorizations`),
      api(`/api/v1/projects/${projectId}/scope-snapshots`)
    ]);
    setTargets(targetList);
    setAuthorizations(authorizationList);
    setSnapshots(snapshotList);
  }, [api]);

  async function selectProject(projectId: number) {
    setSelectedProjectId(projectId);
    setTargets([]);
    setAuthorizations([]);
    setSnapshots([]);
    setSnapshotValidity({});
    setError("");
    try {
      await loadProjectResources(projectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load project records");
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
      setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({});
      setMessage("Project created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    window.localStorage.removeItem("snake_access_token");
    setToken(""); setUser(null); setProjects([]); setSelectedProjectId(null); setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({}); setMessage(""); setError("");
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
                <div className="section-heading"><div><p className="eyebrow">PROJECT #{selectedProjectId}</p><h2>Scope & authorization records</h2></div><button className="text-button" onClick={() => { setSelectedProjectId(null); setTargets([]); setAuthorizations([]); setSnapshots([]); setSnapshotValidity({}); }}>CLOSE WORKSPACE</button></div>
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
              </section>
            )}
          </>
        )}

        <footer>SNAKE SECURITY PLATFORM <span>BUILT FOR AUTHORIZED TESTING ONLY</span></footer>
      </section>
    </main>
  );
}

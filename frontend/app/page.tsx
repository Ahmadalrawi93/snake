"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";

type User = { id: number; email: string; role: string };
type Project = { id: number; name: string; description: string; created_at: string };

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export default function Home() {
  const [token, setToken] = useState("");
  const [user, setUser] = useState<User | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
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
      setMessage("Project created.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create project");
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    window.localStorage.removeItem("snake_access_token");
    setToken(""); setUser(null); setProjects([]); setMessage(""); setError("");
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

        <div className="notice"><b>FOUNDATION MODE</b><span>Only account and project management are active. No scanning or target requests are initiated from this dashboard.</span></div>

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
                  projects.map(project => <article className="project-card" key={project.id}><div><small>PROJECT #{project.id}</small><h3>{project.name}</h3><p>{project.description || "No description provided."}</p></div><time>{new Date(project.created_at).toLocaleDateString()}</time></article>)}
              </div>
            </section>
          </>
        )}

        <footer>SNAKE SECURITY PLATFORM <span>BUILT FOR AUTHORIZED TESTING ONLY</span></footer>
      </section>
    </main>
  );
}

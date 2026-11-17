const modules = [
  ["01", "Reconnaissance", "Asset discovery and attack-surface inventory", "PLANNED"],
  ["02", "Analysis", "Evidence correlation and attack-path reasoning", "PLANNED"],
  ["03", "Validation", "Controlled verification with approval gates", "LOCKED"],
  ["04", "Intelligence", "Reusable knowledge and methodology memory", "PLANNED"]
];

export default function Home() {
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">S</span><div><b>SNAKE</b><small>SECURITY OPERATIONS</small></div></div>
        <div className="nav-label">WORKSPACE</div>
        {["Overview", "AI Agent", "Targets", "Scans", "Findings", "Intelligence", "Methodologies", "Reports"].map((item, i) =>
          <div className={i === 0 ? "nav-item active" : "nav-item"} key={item}><span>{["◈","⌘","◎","⌁","◇","▤","⌬","≡"][i]}</span>{item}</div>
        )}
        <div className="sidebar-bottom"><span className="status-dot" /> FOUNDATION BUILD <small>v0.1.0</small></div>
      </aside>
      <section className="content">
        <header><div><p className="eyebrow">SECURITY WORKSPACE / OVERVIEW</p><h1>Command Center</h1><p className="muted">A controlled environment for authorized security research.</p></div><div className="profile">LOCAL INSTANCE <span>●</span></div></header>
        <div className="notice"><b>FOUNDATION MODE</b><span>Scanning is not enabled. Configure authorization and scope controls before connecting tools.</span></div>
        <div className="metrics">
          <article><small>ACTIVE TARGETS</small><strong>—</strong><span>Not configured</span></article>
          <article><small>RUNNING SCANS</small><strong>0</strong><span>Engine not connected</span></article>
          <article><small>OPEN FINDINGS</small><strong>0</strong><span>No findings recorded</span></article>
          <article><small>AGENT STATUS</small><strong className="pending">STANDBY</strong><span>Orchestration not connected</span></article>
        </div>
        <div className="section-heading"><div><p className="eyebrow">SYSTEM MODULES</p><h2>Operational layers</h2></div><span className="muted">PHASE 01 / FOUNDATION</span></div>
        <div className="modules">{modules.map(([n, title, desc, state]) => <article className="module" key={n}><div className="module-top"><span>{n}</span><small>{state}</small></div><h3>{title}</h3><p>{desc}</p></article>)}</div>
        <footer>SNAKE SECURITY PLATFORM <span>BUILT FOR AUTHORIZED TESTING ONLY</span></footer>
      </section>
    </main>
  );
}

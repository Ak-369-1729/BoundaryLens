import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";
import "./styles.css";
import { Overview } from "./views/Overview";
import { StartScan } from "./views/StartScan";
import { AutoScan } from "./views/AutoScan";
import { ScanDetail } from "./views/ScanDetail";
import { Findings } from "./views/Findings";
import { FindingDetail } from "./views/FindingDetail";
import { Baseline } from "./views/Baseline";
import { Matrix } from "./views/Matrix";
import { Graph } from "./views/Graph";
import { Inventory } from "./views/Inventory";
import { Regression } from "./views/Regression";

const nav = [
  { to: "/overview", icon: "◉", label: "Overview" },
  { to: "/auto", icon: "⚡", label: "Automated scan" },
  { to: "/start", icon: "▶", label: "Manifest scan" },
  { to: "/scans", icon: "≋", label: "Scans" },
  { to: "/findings", icon: "⚑", label: "Findings" },
  { to: "/matrix", icon: "▦", label: "Authorization matrix" },
  { to: "/graph", icon: "⌘", label: "Authorization graph" },
  { to: "/inventory", icon: "☷", label: "Discovery inventory" },
  { to: "/regression", icon: "⟳", label: "Regression" },
  { to: "/baseline", icon: "⇄", label: "Baseline comparison" },
];

function Shell() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo" />
          <div className="brand-name">BoundaryLens</div>
        </div>
        <div className="brand-sub">Role-aware authorization scanner</div>
        <nav className="nav">
          {nav.map((n) => (
            <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? "active" : "")}>
              <span className="nav-icon">{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/auto" element={<AutoScan />} />
          <Route path="/start" element={<StartScan />} />
          <Route path="/scans" element={<Overview recentOnly />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/scans/:scanId/findings/:findingId" element={<FindingDetail />} />
          <Route path="/matrix" element={<Matrix />} />
          <Route path="/graph" element={<Graph />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/regression" element={<Regression />} />
          <Route path="/baseline" element={<Baseline />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <Shell />
    </HashRouter>
  </React.StrictMode>
);

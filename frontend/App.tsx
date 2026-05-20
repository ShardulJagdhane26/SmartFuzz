import React, { useEffect, useState } from "react";
import Navbar    from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import NewScan   from "./pages/NewScan";
import LiveScan  from "./pages/LiveScan";
import Results   from "./pages/Results";
import Scans     from "./pages/Scans";
import Benchmark from "./pages/Benchmark";
import Landing   from "./pages/Landing";
import { ScanConfig } from "./types";
import { getScanStatus } from "./api";

type Page =
  | "landing"
  | "dashboard"
  | "new-scan"
  | "live-scan"
  | "results"
  | "scans"
  | "benchmark";

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>("landing");
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [dashProgress, setDashProgress] = useState(0);
  const [dashFindings, setDashFindings] = useState(0);
  const [isScanning, setIsScanning]     = useState(false);

  const handleScanStarted = (scanId: string, _config: ScanConfig) => {
    setActiveScanId(scanId);
    setDashProgress(0);
    setDashFindings(0);
    setIsScanning(true);
    setCurrentPage("live-scan");
  };

  const handleProgressUpdate = (progress: number, findings: number) => {
    setDashProgress(progress);
    setDashFindings(findings);
  };

  const handleScanComplete = () => {
    setIsScanning(false);
    setCurrentPage("results");
  };

  const handleScanEnded = () => {
    setIsScanning(false);
  };

  const handleViewResults = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentPage("results");
  };

  // App-level scan watcher: keeps the navbar "scanning" badge accurate even
  // when the user navigates away from LiveScan before the scan finishes.
  // Without this, isScanning gets stuck `true` after the LiveScan component
  // unmounts because LiveScan was the only thing polling status.
  useEffect(() => {
    if (!isScanning || !activeScanId) return;
    let cancelled = false;
    const check = async () => {
      try {
        const data = await getScanStatus(activeScanId);
        if (cancelled) return;
        if (["completed", "failed", "cancelled"].includes(data.status)) {
          setIsScanning(false);
        }
      } catch {
        if (!cancelled) setIsScanning(false); // backend unreachable — don't get stuck
      }
    };
    check();
    const id = setInterval(check, 3000);
    return () => { cancelled = true; clearInterval(id); };
  }, [isScanning, activeScanId]);

  const navigate = (page: string) => setCurrentPage(page as Page);

  const renderPage = () => {
    if (currentPage === "landing") {
      return <Landing onStartScan={() => navigate("new-scan")} />;
    }
    switch (currentPage) {
      case "dashboard":
        return (
          <Dashboard
            progress={dashProgress}
            onNewScan={() => navigate("new-scan")}
            onViewLiveScan={() => navigate("live-scan")}
            isScanning={isScanning}
            vulnerabilities={[]}
            totalRequests={dashFindings}
            totalEndpoints={0}
          />
        );
      case "new-scan":
        return <NewScan onScanStarted={handleScanStarted} />;
      case "live-scan":
        return activeScanId ? (
          <LiveScan
            scanId={activeScanId}
            onScanComplete={handleScanComplete}
            onScanEnded={handleScanEnded}
            onProgressUpdate={handleProgressUpdate}
          />
        ) : (
          <div className="p-12 text-slate-400 font-bold">
            No active scan. Start one from Mission Config.
          </div>
        );
      case "results":
        return <Results scanId={activeScanId} />;
      case "scans":
        return <Scans onViewResults={handleViewResults} />;
      case "benchmark":
        return <Benchmark />;
      default:
        return null;
    }
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ backgroundColor: '#080d1a' }}>

      {/* Ambient gradient orbs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none" aria-hidden="true">
        <div className="absolute -top-24 left-1/2 -translate-x-1/2 w-[700px] h-[500px] bg-emerald-500/[0.07] rounded-full blur-[90px]" />
        <div className="absolute -bottom-24 -right-24 w-[500px] h-[400px] bg-violet-600/[0.05] rounded-full blur-[80px]" />
        <div className="absolute top-1/3 -left-24 w-[380px] h-[380px] bg-cyan-500/[0.04] rounded-full blur-[70px]" />
      </div>

      <Navbar activeTab={currentPage} setActiveTab={navigate} isScanning={isScanning} />

      <main className="flex-1 overflow-y-auto relative">
        {currentPage === "landing"
          ? renderPage()
          : (
            <div className="max-w-screen-2xl mx-auto px-10 py-10 lg:px-16 lg:py-12">
              {renderPage()}
            </div>
          )
        }
      </main>
    </div>
  );
}

import { useState, useEffect } from "react";
import HomePage from "./pages/HomePage";
import ReportPage from "./pages/ReportPage";
import ZeroTrustReportPage from "./pages/ZeroTrustReportPage";
import SchedulesPage from "./pages/SchedulesPage";
import { fetchAppsecData, fetchZeroTrustData, fetchUserEmail } from "./services/api";
import { ACCESS_EXPIRED_EVENT, reauthenticateNow } from "./services/access-reauth";
import type { AppSecData, ZeroTrustData, ReportInput } from "./types";

type Phase = "home" | "loading" | "report" | "schedules";

export default function App() {
  const [phase, setPhase]             = useState<Phase>("home");
  const [error, setError]             = useState<string>("");
  const [appsecData, setAppsecData]   = useState<AppSecData | null>(null);
  const [ztData, setZtData]           = useState<ZeroTrustData | null>(null);
  const [reportInput, setReportInput] = useState<ReportInput | null>(null);
  const [userEmail, setUserEmail]     = useState<string | null>(null);
  const [accessExpired, setAccessExpired] = useState(false);

  useEffect(() => {
    fetchUserEmail().then(setUserEmail).catch(() => setUserEmail(null));
  }, []);

  // Fired by access-reauth.ts when an Access login redirect is detected but
  // the automatic re-login navigation was already spent for this expiry
  // episode — the session is dead and needs a deliberate user action.
  useEffect(() => {
    const onExpired = () => setAccessExpired(true);
    window.addEventListener(ACCESS_EXPIRED_EVENT, onExpired);
    return () => window.removeEventListener(ACCESS_EXPIRED_EVENT, onExpired);
  }, []);

  async function handleSubmit(input: ReportInput) {
    setPhase("loading");
    setError("");
    setReportInput(input);
    try {
      if (input.product === "zero-trust") {
        const data = await fetchZeroTrustData(input);
        setZtData(data);
        setAppsecData(null);
      } else {
        const data = await fetchAppsecData(input);
        setAppsecData(data);
        setZtData(null);
      }
      setPhase("report");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to fetch data. Check your token and IDs.");
      setPhase("home");
    }
  }

  function handleReset() {
    setAppsecData(null);
    setZtData(null);
    setReportInput(null);
    setError("");
    setPhase("home");
  }

  if (phase === "schedules") {
    return (
      <>
        <SchedulesPage userEmail={userEmail} onBack={() => setPhase("home")} />
        {accessExpired && <AccessExpiredOverlay />}
      </>
    );
  }

  if (phase === "report" && reportInput) {
    if (reportInput.product === "zero-trust" && ztData) {
      return (
        <>
          <ZeroTrustReportPage data={ztData} input={reportInput} onReset={handleReset} userEmail={userEmail} />
          {accessExpired && <AccessExpiredOverlay />}
        </>
      );
    }
    if (appsecData) {
      return (
        <>
          <ReportPage data={appsecData} input={reportInput} onReset={handleReset} userEmail={userEmail} />
          {accessExpired && <AccessExpiredOverlay />}
        </>
      );
    }
  }

  return (
    <>
      <HomePage
        onSubmit={handleSubmit}
        loading={phase === "loading"}
        error={error}
        userEmail={userEmail}
        onOpenSchedules={() => setPhase("schedules")}
      />
      {accessExpired && <AccessExpiredOverlay />}
    </>
  );
}

/**
 * Blocking overlay shown when the Cloudflare Access session is expired and
 * the automatic re-login navigation was already spent for this expiry
 * episode. Until the user re-authenticates, every API call will keep
 * failing, so there is nothing else useful to do on this page.
 */
function AccessExpiredOverlay() {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        background: "rgba(15, 23, 42, 0.55)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div
        style={{
          maxWidth: 440,
          background: "#fff",
          borderRadius: 12,
          padding: "28px 32px",
          boxShadow: "0 20px 50px rgba(2, 6, 23, 0.35)",
          textAlign: "center",
        }}
      >
        <h2 style={{ margin: "0 0 12px", fontSize: 20, fontWeight: 700, color: "#0f172a" }}>
          Session expired
        </h2>
        <p style={{ margin: "0 0 20px", fontSize: 14, lineHeight: 1.5, color: "#475569" }}>
          This dashboard is protected by Cloudflare Access and your login session has
          expired, so report generation is unavailable until you log in again. You will
          return here automatically afterwards.
        </p>
        <button
          onClick={() => reauthenticateNow()}
          style={{
            width: "100%",
            padding: "10px 16px",
            borderRadius: 8,
            border: "none",
            background: "#f97316",
            color: "#fff",
            fontSize: 14,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Log in again
        </button>
      </div>
    </div>
  );
}

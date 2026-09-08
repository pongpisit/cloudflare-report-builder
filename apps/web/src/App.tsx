import { useState, useEffect } from "react";
import HomePage from "./pages/HomePage";
import ReportPage from "./pages/ReportPage";
import ZeroTrustReportPage from "./pages/ZeroTrustReportPage";
import SchedulesPage from "./pages/SchedulesPage";
import { fetchAppsecData, fetchZeroTrustData, fetchUserEmail } from "./services/api";
import type { AppSecData, ZeroTrustData, ReportInput } from "./types";

type Phase = "home" | "loading" | "report" | "schedules";

export default function App() {
  const [phase, setPhase]             = useState<Phase>("home");
  const [error, setError]             = useState<string>("");
  const [appsecData, setAppsecData]   = useState<AppSecData | null>(null);
  const [ztData, setZtData]           = useState<ZeroTrustData | null>(null);
  const [reportInput, setReportInput] = useState<ReportInput | null>(null);
  const [userEmail, setUserEmail]     = useState<string | null>(null);

  useEffect(() => {
    fetchUserEmail().then(setUserEmail).catch(() => setUserEmail(null));
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
    return <SchedulesPage userEmail={userEmail} onBack={() => setPhase("home")} />;
  }

  if (phase === "report" && reportInput) {
    if (reportInput.product === "zero-trust" && ztData) {
      return <ZeroTrustReportPage data={ztData} input={reportInput} onReset={handleReset} userEmail={userEmail} />;
    }
    if (appsecData) {
      return <ReportPage data={appsecData} input={reportInput} onReset={handleReset} userEmail={userEmail} />;
    }
  }

  return (
    <HomePage
      onSubmit={handleSubmit}
      loading={phase === "loading"}
      error={error}
      userEmail={userEmail}
      onOpenSchedules={() => setPhase("schedules")}
    />
  );
}

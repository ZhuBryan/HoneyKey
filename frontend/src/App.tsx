import {
  BrowserRouter as Router,
  Routes,
  Route,
  useLocation,
} from "react-router-dom";
import { useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { Dashboard } from "./components/Dashboard";
import { About } from "./components/About";
import { EngineerReport } from "./components/EngineerReport";
import { ReportsInbox } from "./components/ReportsInbox";
import { ReportDetail } from "./components/ReportDetail";
import { ToastProvider } from "./contexts/ToastContext";

function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
}

export default function App() {
  return (
    <ToastProvider>
      <Router>
        <ScrollToTop />
        <div className="min-h-screen bg-[#FBEAD2] text-[#023D50] relative">
          <Navbar />
          <div className="relative z-10">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/about" element={<About />} />
              <Route path="/reports" element={<ReportsInbox />} />
              <Route path="/reports/:reportId" element={<ReportDetail />} />
              <Route
                path="/report/engineer"
                element={<EngineerReport />}
              />
            </Routes>
          </div>
        </div>
      </Router>
    </ToastProvider>
  );
}
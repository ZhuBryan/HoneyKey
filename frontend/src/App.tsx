import {
  BrowserRouter as Router,
  Routes,
  Route,
} from "react-router-dom";
import { Navbar } from "./components/Navbar";
import { Dashboard } from "./components/Dashboard";
import { About } from "./components/About";
import { EngineerReport } from "./components/EngineerReport";
import { ReportsInbox } from "./components/ReportsInbox";

export default function App() {
  return (
    <Router>
      <div className="min-h-screen bg-[#FBEAD2] text-[#023D50] relative">
        <Navbar />
        <div className="relative z-10">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/about" element={<About />} />
            <Route path="/reports" element={<ReportsInbox />} />
            <Route
              path="/report/engineer"
              element={<EngineerReport />}
            />
          </Routes>
        </div>
      </div>
    </Router>
  );
}
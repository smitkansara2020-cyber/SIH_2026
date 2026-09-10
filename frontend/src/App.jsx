import "./App.css"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import Alerts from "./pages/Alerts"
import Login from "./pages/Login"
import Signup from "./pages/Signup"
import VerifyOtp from "./pages/VerifyOtp"
import Dashboard from "./pages/Dashboard"
import LiveMonitor from "./pages/LiveMonitor"
import TrafficAnalysis from "./pages/TrafficAnalysis"
import Settings from "./pages/Settings"
import Reports from "./pages/Reports"

function App() {
  return (
    <BrowserRouter>

      <Routes>
        

        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/settings"
          element={<Settings />}
        />

        <Route
          path="/traffic-analysis"
          element={<TrafficAnalysis />}
        />

        <Route
          path="/reports"
          element={<Reports />}
        />

        <Route
          path="/live-monitor"
          element={<LiveMonitor />}
        />

        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/signup"
          element={<Signup />}
        />
        <Route
          path="/alerts"
          element={<Alerts />}
        />

        <Route
          path="/reports"
          element={<Reports />}
        />
        
        <Route
          path="/verify-otp"
          element={<VerifyOtp />}
        />

      </Routes>

    </BrowserRouter>
  )
}

export default App
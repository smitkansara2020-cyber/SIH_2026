import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import Sidebar from "../components/Sidebar"
function Reports() {
  const navigate = useNavigate()
  const user = JSON.parse(
    localStorage.getItem("user")
  )
  const [flows, setFlows] = useState([])

useEffect(() => {

  if (!user?.id) {
    navigate("/login")
    return
  }

  const fetchFlows = async () => {
    try {

      const response = await fetch(
        `http://127.0.0.1:8000/api/recent?limit=100&user_id=${user.id}`
      )

      const data = await response.json()

      console.log("REPORT DATA:", data)

      setFlows(
        Array.isArray(data)
          ? data
          : data.data || []
      )

    } catch (error) {
      console.log("Reports error:", error)
    }
  }

  fetchFlows()

  const interval = setInterval(
    fetchFlows,
    2000
  )

  return () => clearInterval(interval)

}, [])

const logout = async () => {

  if (user?.id) {
    try {

      await fetch(
        `http://127.0.0.1:8000/api/stop-monitoring?user_id=${user.id}`,
        {
          method: "POST"
        }
      )

    } catch (error) {

      console.log(
        "Stop monitoring error:",
        error
      )
    }
  }

  localStorage.removeItem("user")
  navigate("/login")
}

  const normal = flows.filter(
    (f) => f.risk_level === "NORMAL"
  ).length

  const suspicious = flows.filter(
    (f) => f.risk_level === "SUSPICIOUS"
  ).length

  const highRisk = flows.filter(
    (f) => f.risk_level === "HIGH RISK"
  ).length

  const downloadCSV = () => {
    if (flows.length === 0) return

    const headers = Object.keys(flows[0])

    const csvRows = [
      headers.join(","),
      ...flows.map((row) =>
        headers
          .map((header) => `"${row[header] ?? ""}"`)
          .join(",")
      )
    ]

    const blob = new Blob(
      [csvRows.join("\n")],
      { type: "text/csv" }
    )

    const url = URL.createObjectURL(blob)

    const link = document.createElement("a")
    link.href = url
    link.download = "network_security_report.csv"
    link.click()

    URL.revokeObjectURL(url)
  }

  return (
    <div className="dashboard-layout">
    <Sidebar />
      <main className="dashboard-main">

        <div className="top-header">

          <div>
            <h1>Reports</h1>

            <p>
              Security detection summary and export
            </p>
          </div>

        </div>


        <div className="dashboard-cards">

          <div className="metric-card">
            <p>Total Flows</p>
            <h2>{flows.length}</h2>
          </div>

          <div className="metric-card">
            <p>Normal</p>
            <h2>{normal}</h2>
          </div>

          <div className="metric-card">
            <p>Suspicious</p>
            <h2>{suspicious}</h2>
          </div>

          <div className="metric-card">
            <p>High Risk</p>
            <h2>{highRisk}</h2>
          </div>

        </div>


        <div className="table-card">

          <div className="table-header">
            <h3>Export Security Report</h3>
          </div>

          <p>
            Download the latest network detection data
            as a CSV file.
          </p>

          <button
            onClick={downloadCSV}
            style={{
              marginTop: "15px",
              padding: "12px 20px",
              background: "#2563eb",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
              fontWeight: "600"
            }}
          >
            Download CSV Report
          </button>

        </div>

      </main>

    </div>
  )
}

export default Reports
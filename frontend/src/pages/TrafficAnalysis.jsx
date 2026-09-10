import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import Sidebar from "../components/Sidebar"
function TrafficAnalysis() {
  const navigate = useNavigate()

  const user = JSON.parse(
    localStorage.getItem("user")
  )

  const [flows, setFlows] = useState([])

  useEffect(() => {

    if (!user) {
      navigate("/login")
      return
    }

    const fetchFlows = async () => {
      try {

        const response = await fetch(
          `http://127.0.0.1:8000/api/recent?limit=100&user_id=${user.id}`
        )

        const data = await response.json()

        setFlows(
          Array.isArray(data)
            ? data
            : data.data || []
        )

      } catch (error) {
        console.log(
          "Traffic analysis error:",
          error
        )
      }
    }

    fetchFlows()

    const interval = setInterval(
      fetchFlows,
      2000
    )

    return () => clearInterval(interval)

  }, [])


  const normal = flows.filter(
    (f) => f.risk_level === "NORMAL"
  ).length

  const suspicious = flows.filter(
    (f) => f.risk_level === "SUSPICIOUS"
  ).length

  const highRisk = flows.filter(
    (f) => f.risk_level === "HIGH RISK"
  ).length

  const averageRisk =
  flows.length > 0
    ? (
        flows.reduce(
          (sum, f) =>
            sum + (f.final_probability || 0),
          0
        ) / flows.length
      ) * 100
    : 0

    const protocolCounts = flows.reduce(
  (acc, flow) => {
    const protocol =
        flow.protocol?.toUpperCase() || "UNKNOWN"

        acc[protocol] =
        (acc[protocol] || 0) + 1

        return acc
    },
    {}
    )

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

   return (
    <div className="dashboard-layout">

         <Sidebar />


      <main className="dashboard-main">

        <div className="top-header">
          <div>
            <h1>Traffic Analysis</h1>
            <p>
              Network traffic behaviour and risk overview
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

          <div className="metric-card">
            <p>Average Risk</p>
            <h2>{averageRisk.toFixed(1)}%</h2>
            </div>

        </div>

        <div className="table-card">

  <div className="table-header">
    <h3>Protocol Distribution</h3>
  </div>

  {Object.entries(protocolCounts).map(
    ([protocol, count]) => (
      <div
        key={protocol}
        style={{
          display: "flex",
          justifyContent: "space-between",
          padding: "10px 0",
          borderBottom: "1px solid #edf0f5"
        }}
      >
        <strong>{protocol}</strong>
        <span>{count} flows</span>
      </div>
    )
  )}

</div>
        <div className="table-card">

          <div className="table-header">
            <h3>Traffic Summary</h3>
          </div>

          <p>
            Total analysed flows: {flows.length}
          </p>

        </div>

      </main>

    </div>
  )
}

export default TrafficAnalysis
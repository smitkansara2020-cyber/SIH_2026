import { useEffect, useState } from "react"
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts"
import { useNavigate } from "react-router-dom"
import SHAPModal from "../components/SHAPmodal.jsx"

import Sidebar from "../components/Sidebar"
function Dashboard() {
  const navigate = useNavigate()
  
  const user = JSON.parse(localStorage.getItem("user"))
  
  const [dashboardData, setDashboardData] = useState(null)
  const [recentData, setRecentData] = useState([])
  const [graphData, setGraphData] = useState([])
  const [explanationData, setExplanationData] = useState(null)
  const [selectedAnalysis, setSelectedAnalysis] =
    useState(null)
  
  const [analysisLoading, setAnalysisLoading] =
    useState(false)
    const [analysisError, setAnalysisError] =
  useState("")

const fetchData = async () => {
  try {
    if (!user?.id) return

    const dashboardResponse = await fetch(
      `http://127.0.0.1:8000/api/dashboard?user_id=${user.id}`
    )

    const dashboardResult = await dashboardResponse.json()
    setDashboardData(dashboardResult)


    const recentResponse = await fetch(
      `http://127.0.0.1:8000/api/recent?limit=8&user_id=${user.id}`
    )

    const recentResult = await recentResponse.json()

    setRecentData(
      Array.isArray(recentResult)
        ? recentResult
        : recentResult.data || []
    )
    const graphResponse = await fetch(
  `http://127.0.0.1:8000/api/recent?limit=60&user_id=${user.id}`
)

const graphResult = await graphResponse.json()

setGraphData(
  Array.isArray(graphResult)
    ? graphResult
    : graphResult.data || []
)

    const explanationResponse = await fetch(
      `http://127.0.0.1:8000/api/explain/latest?user_id=${user.id}`
    )

    const explanationResult =
      await explanationResponse.json()

    setExplanationData(explanationResult)

  } catch (error) {
    console.log(
      "Dashboard fetch error:",
      error
    )
  }
}

const openAnalysis = async (flowId) => {

  if (flowId == null) return

  try {

    setAnalysisLoading(true)
    setAnalysisError("")
    setSelectedAnalysis(null)

    const response = await fetch(
      `http://127.0.0.1:8000/api/explain/${flowId}?user_id=${user.id}`
    )

    const data = await response.json()

    console.log(
      "SHAP RESPONSE:",
      data
    )

    if (data.success) {

      setSelectedAnalysis(data)

    } else {

      setAnalysisError(
        data.message ||
        "Unable to explain this network flow."
      )
    }

  } catch (error) {

    console.log(
      "SHAP fetch error:",
      error
    )

    setAnalysisError(
      "Unable to connect to AI explanation service."
    )

  } finally {

    setAnalysisLoading(false)

  }
}

useEffect(() => {

  if (!user?.id) {
    navigate("/login")
    return
  }

  const startMonitoring = async () => {
    try {

      const response = await fetch(
        `http://127.0.0.1:8000/api/start-monitoring?user_id=${user.id}`,
        {
          method: "POST"
        }
      )

      const data = await response.json()

      console.log(
        "Monitoring:",
        data.message
      )

    } catch (error) {

      console.log(
        "Monitoring startup error:",
        error
      )
    }
  }

  startMonitoring()

  fetchData()

  const interval = setInterval(
    fetchData,
    3000
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

  const total =
    dashboardData?.total ??
    0

  const normal =
    dashboardData?.normal ??
    0

  const suspicious =
    dashboardData?.suspicious ??
    0

  const highRisk =
    dashboardData?.high_risk ??
    0

  const latest =
  dashboardData?.latest ??
  null

const trafficData = []

const bucketSize = 5

for (
  let i = 0;
  i < graphData.length;
  i += bucketSize
) {

  const bucket =
    graphData.slice(i, i + bucketSize)

  const normalCount =
    bucket.filter(
      row => row.risk_level === "NORMAL"
    ).length

  const suspiciousCount =
    bucket.filter(
      row => row.risk_level === "SUSPICIOUS"
    ).length

  const highRiskCount =
    bucket.filter(
      row => row.risk_level === "HIGH RISK"
    ).length

  const lastFlow =
    bucket[bucket.length - 1]

  trafficData.push({

    time:
      lastFlow?.timestamp
        ? lastFlow.timestamp.split(" ")[1]
        : `${i + 1}`,

    Normal: normalCount,

    Suspicious: suspiciousCount,

    "High Risk": highRiskCount

  })
}

const pieData = [
  { name: "Normal", value: normal },
  { name: "Suspicious", value: suspicious },
  { name: "High Risk", value: highRisk }
]

  return (
    <div className="dashboard-layout">
    <Sidebar />
      <main className="dashboard-main">

<div className="top-header">

  <div>
    <h1>Security Dashboard</h1>

    <p>
      Real-time AI-powered network threat detection
    </p>
  </div>

  <div className="dashboard-user">

    <div className="user-avatar">
      {user?.name
        ? user.name.charAt(0).toUpperCase()
        : "U"}
    </div>

    <div>
      <strong>
        {user?.name || "User"}
      </strong>

      <span>
        SENTINALS Operator
      </span>
    </div>

  </div>

</div>


<div className="dashboard-cards">

  <div className="metric-card metric-total">
    <div className="metric-top">
      <p>Total Flows</p>
      <span className="metric-icon">◎</span>
    </div>

    <h2>{total}</h2>
    <span className="metric-subtext">
      Network flows analyzed
    </span>
  </div>


  <div className="metric-card metric-normal">
    <div className="metric-top">
      <p>Normal</p>
      <span className="metric-icon">✓</span>
    </div>

    <h2>{normal}</h2>

    <span className="metric-subtext normal-text">
      Safe traffic
    </span>
  </div>


  <div className="metric-card metric-suspicious">
    <div className="metric-top">
      <p>Suspicious</p>
      <span className="metric-icon">!</span>
    </div>

    <h2>{suspicious}</h2>

    <span className="metric-subtext suspicious-text">
      Needs attention
    </span>
  </div>


  <div className="metric-card metric-danger">
    <div className="metric-top">
      <p>High Risk</p>
      <span className="metric-icon">⚠</span>
    </div>

    <h2>{highRisk}</h2>

    <span className="metric-subtext danger-text">
      Critical activity
    </span>
  </div>

</div>

    <div className="table-card">

  <div className="table-header">
    <h3>Latest Detection</h3>
  </div>

  {latest ? (
    <div className="latest-detection-grid">

      <div>
        <span>Protocol</span>
        <strong>
          {latest.protocol?.toUpperCase()}
        </strong>
      </div>

      <div>
        <span>Risk Level</span>
        <strong>
          {latest.risk_level}
        </strong>
      </div>

      <div>
        <span>RF Probability</span>
        <strong>
          {(latest.rf_probability * 100).toFixed(1)}%
        </strong>
      </div>

      <div>
        <span>LSTM Probability</span>
        <strong>
          {latest.lstm_probability != null
  ? `${(latest.lstm_probability * 100).toFixed(1)}%`
  : "-"
}
        </strong>
      </div>

      <div>
        <span>Final Risk</span>
        <strong>
          {(latest.final_probability * 100).toFixed(1)}%
        </strong>
      </div>

    </div>
  ) : (
    <p>No detection available</p>
  )}

</div>

        <div className="chart-grid">

<div className="chart-card">
  <h3>Traffic Over Time</h3>

  <div className="chart-container">
  
<ResponsiveContainer width="100%" height="100%">

  <LineChart
    data={trafficData}
    margin={{
      top: 10,
      right: 20,
      left: -15,
      bottom: 0
    }}
  >

    <CartesianGrid
      strokeDasharray="3 3"
      vertical={false}
      stroke="#e2e8f0"
    />

<XAxis
  dataKey="time"
  tick={{
    fill: "#1e293b",
    fontSize: 13,
    fontWeight: 600
  }}
/>

<YAxis
  tick={{
    fill: "#1e293b",
    fontSize: 13,
    fontWeight: 600
  }}
/>

    <Tooltip />

    <Legend />

    <Line
      type="monotone"
      dataKey="Normal"
      stroke="#16a34a"
      strokeWidth={3}
      dot={false}
      activeDot={{ r: 5 }}
    />

    <Line
      type="monotone"
      dataKey="Suspicious"
      stroke="#f59e0b"
      strokeWidth={3}
      dot={false}
      activeDot={{ r: 5 }}
    />

    <Line
      type="monotone"
      dataKey="High Risk"
      stroke="#dc2626"
      strokeWidth={3}
      dot={false}
      activeDot={{ r: 5 }}
    />

  </LineChart>

</ResponsiveContainer>

  </div>
</div>


 <div className="chart-card">

  <h3>Risk Distribution</h3>

  <div style={{ width: "100%", height: "260px" }}>

    <ResponsiveContainer width="100%" height="100%">

      <PieChart>

        <Pie
          data={pieData}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={3}
        >

          <Cell fill="#4285f4" />
          <Cell fill="#f5a623" />
          <Cell fill="#ef4444" />

        </Pie>

        <Tooltip />

      </PieChart>

    </ResponsiveContainer>

  </div>

  <div className="risk-legend">
    <span>🔵 Normal</span>
    <span>🟠 Suspicious</span>
    <span>🔴 High Risk</span>
  </div>

</div>  
        </div>

<div className="table-card">

  <div className="table-header">
    <h3>AI Explanation</h3>
    <span>Explainable AI · SHAP</span>
  </div>

  {explanationData?.success ? (

    <div>

      <div className="explanation-summary">

        <div>
          <span>Risk</span>
          <strong>
            {explanationData.risk_level}
          </strong>
        </div>

        <div>
          <span>Final Probability</span>
          <strong>
            {(
              explanationData.final_probability * 100
            ).toFixed(1)}%
          </strong>
        </div>

        <div>
          <span>Protocol</span>
          <strong>
            {explanationData.protocol?.toUpperCase()}
          </strong>
        </div>

      </div>

      <div className="shap-list">

        {explanationData.explanation?.map(
          (item, index) => (

            <div
              className="shap-item"
              key={index}
            >

              <div>
                <strong>
                  {item.feature}
                </strong>

                <span>
                  {item.impact}
                </span>
              </div>

              <div
                className={
                  item.shap_value > 0
                    ? "shap-value risk-up"
                    : "shap-value risk-down"
                }
              >
                {item.shap_value > 0 ? "↑" : "↓"}

                {Math.abs(
                  item.shap_value
                ).toFixed(4)}
              </div>

            </div>

          )
        )}

      </div>

    </div>

  ) : (

    <p>No explanation available.</p>

  )}

</div>

        <div className="table-card">

          <div className="table-header">

            <h3>Recent Detections</h3>

            <span>
              Auto refresh: 3s
            </span>

          </div>


          <div className="table-wrapper">

            <table>

              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Risk</th>
                  <th>Probability</th>
                </tr>
              </thead>

              <tbody>

                {recentData.length === 0 ? (

                  <tr>
                    <td
                      colSpan="6"
                      className="empty-table"
                    >
                      No detection data available
                    </td>
                  </tr>

                ) : (

                  recentData.map((row, index) => (

                    <tr
                      key={row.flow_id ?? index}
                      onClick={() =>
                        openAnalysis(row.flow_id)
                      }
                      style={{ cursor: "pointer" }}
                    >

                      <td>
                        {row.timestamp || "-"}
                      </td>

                      <td>
                        {row.src_ip || "-"}
                      </td>

                      <td>
                        {row.dst_ip || "-"}
                      </td>

                      <td>
                        {row.protocol || "-"}
                      </td>

                      <td>
                        <span
                          className={`risk-badge ${
                            row.risk_level
                              ?.toLowerCase()
                              .replace(" ", "-")
                          }`}
                        >
                          {row.risk_level || "Unknown"}
                        </span>
                      </td>

                      <td>
                        {
                          row.final_probability !== undefined
                            ? `${(
                                row.final_probability * 100
                              ).toFixed(1)}%`
                            : "-"
                        }
                      </td>

                    </tr>

                  ))

                )}

              </tbody>

            </table>
                
          </div>
<SHAPModal
  data={selectedAnalysis}
  loading={analysisLoading}
  error={analysisError}
  onClose={() => {
    setSelectedAnalysis(null)
    setAnalysisError("")
  }}
/>
        </div>

      </main>

    </div>
  )
}

export default Dashboard
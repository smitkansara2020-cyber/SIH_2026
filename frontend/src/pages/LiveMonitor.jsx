import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import Sidebar from "../components/Sidebar"
function LiveMonitor() {
  const navigate = useNavigate()

  const user = JSON.parse(
    localStorage.getItem("user")
  )

  const [flows, setFlows] = useState([])

  const fetchFlows = async () => {
    try {
      if (!user?.id) return

      const response = await fetch(
        `http://127.0.0.1:8000/api/recent?limit=20&user_id=${user.id}`
      )

      const data = await response.json()

      setFlows(
        Array.isArray(data)
          ? data
          : data.data || []
      )

    } catch (error) {
      console.log("Live monitor error:", error)
    }
  }

  useEffect(() => {
    if (!user) {
      navigate("/login")
      return
    }

    fetchFlows()

    const interval = setInterval(
      fetchFlows,
      2000
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


  return (
    <div className="dashboard-layout">

  
    <Sidebar />

      <main className="dashboard-main">

        <div className="top-header">
          <div>
            <h1>Live Network Monitor</h1>

            <p>
              Real-time network flow detection
            </p>
          </div>

          <div className="user-box">
            <div className="status-dot"></div>

            <div>
              <strong>Monitoring</strong>
              <span>Refresh every 2 seconds</span>
            </div>
          </div>
        </div>


        <div className="table-card">

          <div className="table-header">
            <h3>Live Network Flows</h3>

            <span>
              {flows.length} recent flows
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
                  <th>RF</th>
                  <th>LSTM</th>
                  <th>Final Risk</th>
                  <th>Status</th>
                </tr>
              </thead>


              <tbody>

                {flows.length === 0 ? (

                  <tr>
                    <td
                      colSpan="8"
                      className="empty-table"
                    >
                      Waiting for live network traffic...
                    </td>
                  </tr>

                ) : (

                  flows.map((row, index) => (

                    <tr key={index}>

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
                        {row.protocol?.toUpperCase() || "-"}
                      </td>

                      <td>
                        {
                          row.rf_probability !== undefined
                            ? `${(
                                row.rf_probability * 100
                              ).toFixed(1)}%`
                            : "-"
                        }
                      </td>

                      <td>
                        {row.lstm_probability != null
  ? `${(row.lstm_probability * 100).toFixed(1)}%`
  : "-"
}
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

                      <td>
                        <span
                          className={`risk-badge ${
                            row.risk_level
                              ?.toLowerCase()
                              .replace(" ", "-")
                          }`}
                        >
                          {row.risk_level || "UNKNOWN"}
                        </span>
                      </td>

                    </tr>

                  ))

                )}

              </tbody>

            </table>

          </div>

        </div>

      </main>

    </div>
  )
}

export default LiveMonitor
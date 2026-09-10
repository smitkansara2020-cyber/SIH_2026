import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import SHAPModal from "../components/SHAPmodal.jsx"

import Sidebar from "../components/Sidebar"
function Alerts() {
  const navigate = useNavigate()

  const user = JSON.parse(
    localStorage.getItem("user")
  )

  const [alerts, setAlerts] = useState([])
  const [showBlockedModal, setShowBlockedModal] =
  useState(false)
  const [blockedIps, setBlockedIps] =
  useState([])
  const [selectedAnalysis, setSelectedAnalysis] =
  useState(null)

const [analysisLoading, setAnalysisLoading] =
  useState(false)

  const [analysisError, setAnalysisError] =
  useState("")

  
  const fetchAlerts = async () => {
    try {
      if (!user?.id) return

      const response = await fetch(
        `http://127.0.0.1:8000/api/alerts?user_id=${user.id}`
      )

      const data = await response.json()

      setAlerts(
        Array.isArray(data)
          ? data
          : data.data || []
      )

    } catch (error) {
      console.log("Alerts error:", error)
    }
  }

  const fetchBlockedIps = async () => {

  try {

    if (!user?.id) return

    const response = await fetch(
      `http://127.0.0.1:8000/api/blocked-ips?user_id=${user.id}`
    )

    const data =
      await response.json()

    setBlockedIps(
      Array.isArray(data)
        ? data
        : []
    )

  } catch (error) {

    console.log(
      "Blocked IP fetch error:",
      error
    )

  }
}

const unblockThreat = async (ipAddress) => {

  const confirmed =
    window.confirm(
      `Unblock ${ipAddress}?`
    )

  if (!confirmed) return


  try {

    const response = await fetch(
      "http://127.0.0.1:8000/api/unblock-ip",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          user_id: user.id,
          ip_address: ipAddress
        })
      }
    )


    const data =
      await response.json()


    if (data.success) {

      alert(
        `${ipAddress} unblocked successfully`
      )

      fetchBlockedIps()

    } else {

      alert(
        data.message ||
        "Unable to unblock IP"
      )
    }

  } catch (error) {

    console.log(
      "Unblock error:",
      error
    )

  }
}


  const openAnalysis = async (flowId) => {

  console.log("Clicked alert flow:", flowId)

  if (flowId == null) return

  try {

    setAnalysisLoading(true)
    setSelectedAnalysis(null)

    const response = await fetch(
      `http://127.0.0.1:8000/api/explain/${flowId}?user_id=${user.id}`
    )

    const data = await response.json()

    console.log(
      "ALERT SHAP RESPONSE:",
      data
    )

    if (data.success) {

      setSelectedAnalysis(data)

    } else {

      console.log(
        "SHAP backend error:",
        data.message
      )
    }

  } catch (error) {

    console.log(
      "Alert SHAP error:",
      error
    )

  } finally {

    setAnalysisLoading(false)

  }
}
  useEffect(() => {
    if (!user) {
      navigate("/login")
      return
    }

fetchAlerts()
fetchBlockedIps()

const interval = setInterval(
  () => {
    fetchAlerts()
    fetchBlockedIps()
  },
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
  return (
    <div className="dashboard-layout">
    <Sidebar />
      <main className="dashboard-main">

        <div className="top-header">

          <div>
            <h1>Security Alerts</h1>

            <p>
              Suspicious and high-risk network activity
            </p>
          </div>

        </div>


        <div className="dashboard-cards">

          <div className="metric-card">
            <p>Total Alerts</p>

            <h2>{alerts.length}</h2>

            <span className="suspicious-text">
              Requires review
            </span>
          </div>


          <div className="metric-card">
            <p>Suspicious</p>

            <h2>
              {
                alerts.filter(
                  (a) =>
                    a.risk_level === "SUSPICIOUS"
                ).length
              }
            </h2>
          </div>


          <div className="metric-card">
            <p>High Risk</p>

            <h2>
              {
                alerts.filter(
                  (a) =>
                    a.risk_level === "HIGH RISK"
                ).length
              }
            </h2>

            <span className="danger-text">
              Critical alerts
            </span>
          </div>

        </div>

       <div
  className="metric-card blocked-card"
  onClick={() => setShowBlockedModal(true)}
  style={{ cursor: "pointer" }}
>
  <p>Blocked Threats</p>

  <h2>{blockedIps.length}</h2>

  <span className="danger-text">
    Click to manage
  </span>
</div>

        <div className="table-card">

          <div className="table-header">

            <h3>Detected Threats</h3>

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

                {alerts.length === 0 ? (

                  <tr>
                    <td
                      colSpan="6"
                      className="empty-table"
                    >
                      No alerts detected
                    </td>
                  </tr>

                ) : (

                  alerts.map((row, index) => (

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
                          {row.risk_level}
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

        </div>

                <div
  className="table-card"
  style={{ marginTop: "22px" }}
>

  <div className="table-header">

    <h3>Blocked Threats</h3>

    <span>
      Windows Firewall
    </span>

  </div>


  <div className="table-wrapper">

    <table>

      <thead>

        <tr>
          <th>IP Address</th>
          <th>Blocked At</th>
          <th>Risk</th>
          <th>Status</th>
          <th>Action</th>
        </tr>

      </thead>


      <tbody>

        {blockedIps.length === 0 ? (

          <tr>

            <td
              colSpan="5"
              className="empty-table"
            >
              No blocked threats
            </td>

          </tr>

        ) : (

          blockedIps.map(
            (item, index) => (

              <tr key={index}>

                <td>
                  <strong>
                    {item.ip_address}
                  </strong>
                </td>


                <td>
                  {item.blocked_at || "-"}
                </td>


                <td>

                  <span
                    className="risk-badge high-risk"
                  >
                    {item.risk_level}
                  </span>

                </td>


                <td>

                  <span
                    className="blocked-status"
                  >
                    🛡 BLOCKED
                  </span>

                </td>


                <td>

                  <button
                    className="unblock-btn"

                    onClick={() =>
                      unblockThreat(
                        item.ip_address
                      )
                    }
                  >
                    Unblock
                  </button>

                </td>

              </tr>

            )
          )

        )}

      </tbody>

    </table>

  </div>

</div>
<div
  className="table-card"
  style={{ marginTop: "22px" }}
>

  <div className="table-header">

    <h3>Blocked Threats</h3>

    <span>
      Windows Firewall
    </span>

  </div>


  <div className="table-wrapper">

    <table>

      <thead>

        <tr>
          <th>IP Address</th>
          <th>Blocked At</th>
          <th>Risk</th>
          <th>Status</th>
          <th>Action</th>
        </tr>

      </thead>


      <tbody>

        {blockedIps.length === 0 ? (

          <tr>

            <td
              colSpan="5"
              className="empty-table"
            >
              No blocked threats
            </td>

          </tr>

        ) : (

          blockedIps.map(
            (item, index) => (

              <tr key={index}>

                <td>
                  <strong>
                    {item.ip_address}
                  </strong>
                </td>


                <td>
                  {item.blocked_at || "-"}
                </td>


                <td>

                  <span
                    className="risk-badge high-risk"
                  >
                    {item.risk_level}
                  </span>

                </td>


                <td>

                  <span className="blocked-status">
                    🛡 BLOCKED
                  </span>

                </td>


                <td>

                  <button
                    className="unblock-btn"

                    onClick={() =>
                      unblockThreat(
                        item.ip_address
                      )
                    }
                  >
                    Unblock
                  </button>

                </td>

              </tr>

            )
          )

        )}

      </tbody>

    </table>

  </div>

</div>
      </main>

{showBlockedModal && (

  <div className="blocked-modal-overlay">

    <div className="blocked-modal">

      <div className="blocked-modal-header">

        <div>
          <h2>Blocked Threats</h2>
          <p>
            IPs blocked by Windows Firewall
          </p>
        </div>

        <button
          className="blocked-modal-close"
          onClick={() =>
            setShowBlockedModal(false)
          }
        >
          ✕
        </button>

      </div>


      <div className="blocked-modal-list">

        {blockedIps.length === 0 ? (

          <div className="no-blocked-ips">
            No blocked IP addresses
          </div>

        ) : (

          blockedIps.map(
            (item, index) => (

              <div
                className="blocked-ip-item"
                key={index}
              >

                <div>

                  <strong>
                    {item.ip_address}
                  </strong>

                  <span>
                    {item.risk_level || "Threat"}
                  </span>

                  <small>
                    Blocked:{" "}
                    {item.blocked_at || "-"}
                  </small>

                </div>


                <button
                  className="unblock-btn"

                  onClick={() =>
                    unblockThreat(
                      item.ip_address
                    )
                  }
                >
                  Unblock
                </button>

              </div>

            )
          )

        )}

      </div>

    </div>

  </div>

)}

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
  )
}

export default Alerts
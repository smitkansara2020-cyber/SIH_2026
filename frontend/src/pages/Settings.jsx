import { useNavigate } from "react-router-dom"

import Sidebar from "../components/Sidebar"

function Settings() {

  const navigate = useNavigate()

  const user = JSON.parse(
    localStorage.getItem("user")
  )


  // ===============================
  // LOGOUT
  // ===============================

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


  // ===============================
  // CLEAR HISTORY
  // ===============================

  const clearHistory = async () => {

    if (!user?.id) return

    const confirmed = window.confirm(
      "Delete all your previous detection history?"
    )

    if (!confirmed) return


    try {

      const response = await fetch(
        `http://127.0.0.1:8000/api/logs?user_id=${user.id}`,
        {
          method: "DELETE"
        }
      )

      const data =
        await response.json()

      alert(data.message)

    } catch (error) {

      console.log(
        "Clear history error:",
        error
      )

      alert(
        "Unable to clear detection history"
      )

    }
  }


  return (

    <div className="dashboard-layout">

    <Sidebar />

      <main className="dashboard-main">


        <div className="top-header">

          <div>

            <h1>
              Settings
            </h1>

            <p>
              Detection and model configuration
            </p>

          </div>

        </div>



        {/* THRESHOLDS */}

        <div className="table-card">

          <div className="table-header">

            <h3>
              Detection Thresholds
            </h3>

          </div>

          <p>
            <strong>Normal:</strong>{" "}
            below 60%
          </p>

          <p>
            <strong>Suspicious:</strong>{" "}
            60% - 75%
          </p>

          <p>
            <strong>High Risk:</strong>{" "}
            75% and above
          </p>

        </div>



        {/* ENSEMBLE */}

        <div
          className="table-card"
          style={{
            marginTop: "20px"
          }}
        >

          <div className="table-header">

            <h3>
              Ensemble Configuration
            </h3>

          </div>

          <p>
            <strong>
              Random Forest Weight:
            </strong>{" "}
            75%
          </p>

          <p>
            <strong>
              LSTM Weight:
            </strong>{" "}
            25%
          </p>

          <p
            style={{
              color: "#64748b"
            }}
          >
            These values can be tuned
            after final model evaluation.
          </p>

        </div>



        {/* HISTORY */}

        <div
          className="table-card"
          style={{
            marginTop: "20px"
          }}
        >

          <div className="table-header">

            <h3>
              Detection History
            </h3>

          </div>

          <p>
            Delete all previously stored
            network detection logs for your
            account and start fresh.
          </p>

          <button
            className="clear-history-btn"
            onClick={clearHistory}
          >
            Clear Detection History
          </button>

        </div>


      </main>

    </div>
  )
}


export default Settings
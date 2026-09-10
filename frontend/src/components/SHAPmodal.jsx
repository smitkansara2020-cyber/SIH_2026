function SHAPModal({
  data,
  loading,
  error,
  onClose
}) {

  if (!data && !loading && !error) {
    return null
  }

  const user = JSON.parse(
  localStorage.getItem("user")
)

const blockThreat = async () => {

  if (!data?.flow_id || !user?.id) {
    return
  }


  const confirmed = window.confirm(
    "Block the remote IP using Windows Firewall?"
  )

  if (!confirmed) return


  try {

    const response = await fetch(
      "http://127.0.0.1:8000/api/block-flow",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          user_id: user.id,
          flow_id: data.flow_id
        })
      }
    )


    const result =
      await response.json()


    if (result.success) {

      alert(
        `Threat blocked!\n\nIP: ${result.blocked_ip}`
      )

    } else {

      alert(
        result.message ||
        "Unable to block this IP."
      )
    }


  } catch (error) {

    console.log(
      "Block threat error:",
      error
    )

    alert(
      "Unable to contact firewall service."
    )
  }
}

  return (
    <div className="shap-modal-overlay">

      <div className="shap-modal">

        <button
          className="shap-modal-close"
          onClick={onClose}
        >
          ✕
        </button>

{loading ? (

  <p>Analyzing network flow...</p>

) : error ? (

  <div className="shap-error">

    <h2>AI Analysis Failed</h2>

    <p>{error}</p>

    <button onClick={onClose}>
      Close
    </button>

  </div>

) : (

  <>
            <div className="shap-modal-header">

              <div>
                <h2>AI Security Analysis</h2>
                <p>
                  SENTINALS Explainable AI
                </p>
              </div>

              <span
                className={`risk-badge ${
                  data.risk_level
                    ?.toLowerCase()
                    .replace(" ", "-")
                }`}
              >
                {data.risk_level}
              </span>

            </div>


            <div className="shap-summary">

              <h3>
                Risk Score:{" "}
                {(data.final_probability * 100)
                  .toFixed(1)}%
              </h3>

              <p>{data.summary}</p>

            </div>


            <div className="shap-network-info">

              <div>
                <span>Source</span>
                <strong>{data.src_ip}</strong>
              </div>

              <div>
                <span>Destination</span>
                <strong>{data.dst_ip}</strong>
              </div>

              <div>
                <span>Protocol</span>
                <strong>
                  {data.protocol?.toUpperCase()}
                </strong>
              </div>

            </div>


            <h3>Model Analysis</h3>

            <div className="shap-model-grid">

              <div>
                <span>Random Forest</span>
                <strong>
                  {(data.rf_probability * 100)
                    .toFixed(1)}%
                </strong>
              </div>

              <div>
                <span>LSTM</span>

                <strong>
                  {data.lstm_probability != null
                    ? `${(
                        data.lstm_probability * 100
                      ).toFixed(1)}%`
                    : "Warming up"}
                </strong>
              </div>

              <div>
                <span>Model Agreement</span>

                <strong>
                  {data.model_agreement?.level}
                </strong>
              </div>

            </div>


            {data.model_agreement?.message && (
              <p className="agreement-message">
                {data.model_agreement.message}
              </p>
            )}


            <h3>Why did SENTINALS make this decision?</h3>

            <div className="shap-explanation-list">

              {data.explanation?.map(
                (item, index) => (

                  <div
                    className="shap-explanation-card"
                    key={index}
                  >

                    <div className="shap-feature-title">

                      <strong>
                        {item.shap_value > 0
                          ? "↑ "
                          : "↓ "}

                        {item.feature}
                      </strong>

                      <span>
                        {item.impact}
                      </span>

                    </div>

                    <p>
                      <strong>Observation:</strong>{" "}
                      {item.cause}
                    </p>

                    <p>
                      <strong>Why it matters:</strong>{" "}
                      {item.why}
                    </p>

                    <p>
                      <strong>Suggested check:</strong>{" "}
                      {item.action}
                    </p>

                  </div>

                )
              )}

            </div>


            <div className="shap-recommendation">

              <h3>Recommended Action</h3>

              <p>
                {data.recommendation}
              </p>

            </div>

              {data?.risk_level !== "NORMAL" && (

  <div className="threat-actions">

    <button
      className="block-threat-btn"
      onClick={blockThreat}
    >
      🛡 Block Remote IP
    </button>

  </div>

)}

            <div className="shap-note">

              {data.shap_note}

            </div>

          </>
        )}

      </div>

    </div>
  )
}

export default SHAPModal
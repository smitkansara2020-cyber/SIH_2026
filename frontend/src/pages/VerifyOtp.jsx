import { useState } from "react"
import { useNavigate } from "react-router-dom"


function VerifyOtp() {

  const navigate = useNavigate()

  const [otp, setOtp] = useState("")
  const [message, setMessage] = useState("")

  const email = localStorage.getItem("signup_email")


  const handleVerify = async (e) => {

    e.preventDefault()

    try {

      const response = await fetch(
        "http://127.0.0.1:8000/api/verify-otp",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            email: email,
            otp: otp
          })
        }
      )

      const data = await response.json()

      if (data.success) {

        setMessage("Account verified successfully")

        localStorage.removeItem("signup_otp")

        setTimeout(() => {
          navigate("/login")
        }, 1200)

      } else {

        setMessage(data.message)
      }

    } catch (error) {

      setMessage(
        "Unable to connect to server"
      )
    }
  }


  return (
    <div className="auth-page">

      <div className="auth-card">

        <h1>Verify OTP</h1>

        <p>
          Enter the 6-digit OTP for
        </p>

        <p>
          <strong>{email}</strong>
        </p>

        <form onSubmit={handleVerify}>

          <input
            type="text"
            placeholder="Enter 6-digit OTP"
            value={otp}
            maxLength="6"
            onChange={(e) =>
              setOtp(e.target.value.replace(/\D/g, ""))
            }
            required
          />

          <button type="submit">
            Verify OTP
          </button>

        </form>

        {message && (
          <p>{message}</p>
        )}

      </div>

    </div>
  )
}


export default VerifyOtp
import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"

function Signup() {

  const navigate = useNavigate()

  const [name, setName] = useState("")
  const [mobile, setMobile] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [message, setMessage] = useState("")

  // NEW: choose where OTP should be sent
  const [otpMethod, setOtpMethod] = useState("email")

  const handleSignup = async (e) => {

    e.preventDefault()

    try {

      const response = await fetch(
        "http://127.0.0.1:8000/api/signup",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            name,
            mobile,
            email,
            password,

            // NEW
            otp_method: otpMethod
          })
        }
      )

      const data = await response.json()

      if (data.success) {

        localStorage.setItem(
          "signup_email",
          email
        )

        localStorage.setItem(
          "signup_mobile",
          mobile
        )

        localStorage.setItem(
          "otp_method",
          otpMethod
        )

        navigate("/verify-otp")

      } else {

        setMessage(data.message)
      }

} catch (error) {

  console.log("Signup error:", error)

  setMessage(
    "Signup failed. Check console."
  )
}
  }


  return (
    <div className="auth-page">

      <div className="auth-card">

        <h1>Create Account</h1>

        <p>
          Create your security platform account.
        </p>

        <form onSubmit={handleSignup}>

          <input
            type="text"
            placeholder="Full name"
            value={name}
            onChange={(e) =>
              setName(e.target.value)
            }
            required
          />

          <input
            type="tel"
            placeholder="Mobile number"
            value={mobile}
            onChange={(e) =>
              setMobile(e.target.value)
            }
            required
          />

          <input
            type="email"
            placeholder="Email address"
            value={email}
            onChange={(e) =>
              setEmail(e.target.value)
            }
            required
          />

          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) =>
              setPassword(e.target.value)
            }
            required
          />


          {/* NEW OTP METHOD SECTION */}

          <div className="otp-method">

            <p>
              Send verification code via:
            </p>

            <label>

              <input
                type="radio"
                value="email"
                checked={otpMethod === "email"}
                onChange={(e) =>
                  setOtpMethod(e.target.value)
                }
              />

              Email

            </label>

            <label>

              <input
                type="radio"
                value="mobile"
                checked={otpMethod === "mobile"}
                onChange={(e) =>
                  setOtpMethod(e.target.value)
                }
              />

              Mobile

            </label>

          </div>


          <button type="submit">
            Create Account
          </button>

        </form>


        {message && (
          <p>{message}</p>
        )}


        <div className="auth-footer">

          <p>
            Already have an account?{" "}

            <Link to="/login">
              Sign in
            </Link>
          </p>

        </div>

      </div>

    </div>
  )
}

export default Signup
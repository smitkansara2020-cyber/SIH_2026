import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"

function Login() {

  const navigate = useNavigate()

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [message, setMessage] = useState("")


const handleLogin = async (e) => {

  e.preventDefault()

  try {

    const response = await fetch(
      "http://127.0.0.1:8000/api/login",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password: password
        })
      }
    )

    const data = await response.json()

    if (data.success) {

      localStorage.setItem(
        "user",
        JSON.stringify(data.user)
      )

      navigate("/dashboard")

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

      <h1>Welcome Back</h1>

      <p>
        Sign in to access your security dashboard.
      </p>

      <form onSubmit={handleLogin}>

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

        <button type="submit">
          Sign In
        </button>

      </form>

      {message && (
        <p>{message}</p>
      )}

      <div className="auth-footer">

        <p>
          Don't have an account?{" "}

          <Link to="/signup">
            Create account
          </Link>
        </p>

      </div>

    </div>

  </div>
    )
}


export default Login
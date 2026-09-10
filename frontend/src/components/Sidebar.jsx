import { useLocation, useNavigate } from "react-router-dom"

import {
  LayoutDashboard,
  Activity,
  Bell,
  BarChart3,
  FileText,
  Settings,
  LogOut,
  Shield
} from "lucide-react"

function Sidebar() {

  const navigate = useNavigate()
  const location = useLocation()

  const user = JSON.parse(
    localStorage.getItem("user")
  )

  const items = [
    {
      name: "Dashboard",
      path: "/dashboard",
      icon: LayoutDashboard
    },
    {
      name: "Live Monitor",
      path: "/live-monitor",
      icon: Activity
    },
    {
      name: "Alerts",
      path: "/alerts",
      icon: Bell
    },
    {
      name: "Traffic Analysis",
      path: "/traffic-analysis",
      icon: BarChart3
    },
    {
      name: "Reports",
      path: "/reports",
      icon: FileText
    },
    {
      name: "Settings",
      path: "/settings",
      icon: Settings
    }
  ]

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
          "Logout error:",
          error
        )
      }
    }

    localStorage.removeItem("user")
    navigate("/login")
  }

  return (

    <aside className="sidebar">

      <div className="sidebar-brand">

        <Shield size={28} />

        <div>
          <h2>SENTINALS</h2>
          <p>AI-POWERED IDS</p>
        </div>

      </div>


      <nav className="sidebar-menu">

        {items.map((item) => {

          const Icon = item.icon

          const isActive =
            location.pathname === item.path

          return (

            <button
              key={item.path}
              type="button"
              className={`sidebar-item ${
                isActive
                  ? "sidebar-item-active"
                  : ""
              }`}
              onClick={() =>
                navigate(item.path)
              }
            >

              <Icon size={20} />

              <span>
                {item.name}
              </span>

            </button>

          )
        })}

      </nav>


      <button
        type="button"
        className="sidebar-logout"
        onClick={logout}
      >

        <LogOut size={20} />

        <span>Logout</span>

      </button>

    </aside>
  )
}

export default Sidebar
import React from "react"
import ReactDOM from "react-dom/client"
import { createBrowserRouter, RouterProvider } from "react-router-dom"
import { Layout } from "./components/Layout"
import { Projects } from "./pages/Projects"
import { ProjectDetail } from "./pages/ProjectDetail"
import { ScanDetail } from "./pages/ScanDetail"
import { Settings } from "./pages/Settings"
import "./index.css"

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <Projects /> },
      { path: "projects/:id", element: <ProjectDetail /> },
      { path: "scans/:id", element: <ScanDetail /> },
      { path: "settings", element: <Settings /> },
    ],
  },
])

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)

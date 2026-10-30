import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './styles/base.css'
import App from './App'
import { AuthProvider } from './auth/AuthContext'
import { readTheme, setTheme } from './styles/theme'

// public/theme.js chose the token block before paint; this also points the
// browser chrome (theme-color, color-scheme) at the stored choice.
setTheme(readTheme())

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
)

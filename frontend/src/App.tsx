import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './router/ProtectedRoute';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AlertsPage } from './pages/AlertsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { HealthPage } from './pages/HealthPage';
import { EvaluationPage } from './pages/EvaluationPage';
import { EntityPage } from './pages/EntityPage';

function RootGuard() {
  const sessionToken = typeof window !== 'undefined'
    ? localStorage.getItem('soc_session_token') || localStorage.getItem('access_token')
    : null;

  if (!sessionToken) {
    return <Navigate to="/login" replace />;
  }

  return <DashboardPage />;
}

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Authentication Route */}
          <Route path="/login" element={<LoginPage />} />

          {/* Protected SOC Console Routes */}
          <Route
            element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            }
          >
            <Route index element={<RootGuard />} />
            <Route path="dashboard" element={<Navigate to="/" replace />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="incidents" element={<IncidentsPage />} />
            <Route path="evaluation" element={<EvaluationPage />} />
            <Route path="entities" element={<EntityPage />} />
            <Route path="entities/:id" element={<EntityPage />} />
            <Route path="health" element={<HealthPage />} />
          </Route>

          {/* Catch-all Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;

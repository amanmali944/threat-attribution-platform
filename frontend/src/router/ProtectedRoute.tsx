import type { ReactNode } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { RefreshCw } from 'lucide-react';

interface ProtectedRouteProps {
  children?: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const sessionToken = typeof window !== 'undefined'
    ? localStorage.getItem('soc_session_token') || localStorage.getItem('access_token')
    : null;

  // Immediate redirect if no session key exists in localStorage
  if (!sessionToken) {
    return <Navigate to="/login" replace />;
  }

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-black text-white">
        <div className="flex flex-col items-center gap-4 border border-[#1f1f1f] bg-black/90 p-8">
          <RefreshCw className="h-8 w-8 animate-spin text-[#c81b1c]" />
          <div className="h-1 w-48 bg-[#1a1a1a]">
            <div className="h-full w-1/2 bg-[#c81b1c] animate-pulse" />
          </div>
          <span className="font-jb text-xs tracking-widest text-[#949494] uppercase">
            Verifying SOC Authentication...
          </span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return children ? <>{children}</> : <Outlet />;
}

export default ProtectedRoute;

import type { ReactNode } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { ShieldAlert } from 'lucide-react';

interface ProtectedRouteProps {
  children?: ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-[#030712] text-[#f1f5f9]">
        <div className="flex flex-col items-center gap-4">
          <ShieldAlert className="h-10 w-10 animate-bounce text-[#22d3ee]" />
          <div className="h-2 w-48 overflow-hidden rounded-full bg-[#1e293b]">
            <div className="h-full w-1/2 animate-pulse rounded-full bg-[#22d3ee]" />
          </div>
          <span className="font-mono text-xs tracking-widest text-[#94a3b8] uppercase">
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

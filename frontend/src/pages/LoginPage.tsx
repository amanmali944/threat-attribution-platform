import { useState, type FormEvent } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { Shield, Lock, User, AlertCircle, KeyRound, Terminal } from 'lucide-react';

export function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // If already logged in, redirect straight to dashboard
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(username, password);
      navigate('/');
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setError(axiosErr.response?.data?.detail || 'Invalid username or password.');
      } else {
        setError('Network error or server unreachable. Please try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const setCredentials = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
  };

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-[#030712] px-4 py-12">
      <div className="w-full max-w-md space-y-8 rounded-2xl border border-[#334155] bg-[#0f172a]/90 p-8 shadow-2xl backdrop-blur-xl">
        {/* Header / Brand */}
        <div className="flex flex-col items-center text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-[#22d3ee]/40 bg-[#22d3ee]/10 text-[#22d3ee] shadow-[0_0_20px_rgba(34,211,238,0.2)]">
            <Shield className="h-8 w-8" />
          </div>
          <h2 className="mt-4 text-2xl font-bold tracking-tight text-[#f1f5f9]">
            THREAT ATTRIBUTION
          </h2>
          <p className="mt-1 font-mono text-xs text-[#94a3b8]">
            ENTERPRISE SOC SECURITY GATEWAY
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="flex items-center gap-3 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-400">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-5">
          <div>
            <label className="block text-xs font-mono font-medium uppercase text-[#94a3b8]">
              Operator Identity (Username)
            </label>
            <div className="relative mt-1">
              <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#64748b]">
                <User className="h-4 w-4" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                className="w-full rounded-lg border border-[#334155] bg-[#030712] py-2.5 pl-10 pr-4 text-sm text-[#f1f5f9] placeholder-[#64748b] transition focus:border-[#22d3ee]"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono font-medium uppercase text-[#94a3b8]">
              Passkey / Password
            </label>
            <div className="relative mt-1">
              <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#64748b]">
                <Lock className="h-4 w-4" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full rounded-lg border border-[#334155] bg-[#030712] py-2.5 pl-10 pr-4 text-sm text-[#f1f5f9] placeholder-[#64748b] transition focus:border-[#22d3ee]"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#22d3ee] py-2.5 font-medium text-[#030712] transition hover:bg-[#06b6d4] active:scale-[0.98] disabled:opacity-50"
          >
            <KeyRound className="h-4 w-4" />
            <span>{isSubmitting ? 'Authenticating...' : 'Sign In to Console'}</span>
          </button>
        </form>

        {/* Quick-Fill Seed Credentials for Testing */}
        <div className="border-t border-[#334155] pt-4">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#64748b]">
            <Terminal className="h-3 w-3" />
            <span>QUICK-FILL TEST ACCOUNTS</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setCredentials('admin', 'Admin123!')}
              className="rounded border border-[#334155] bg-[#1e293b] px-2.5 py-1 text-xs text-[#94a3b8] transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            >
              admin (SOC Admin)
            </button>
            <button
              type="button"
              onClick={() => setCredentials('analyst', 'Analyst123!')}
              className="rounded border border-[#334155] bg-[#1e293b] px-2.5 py-1 text-xs text-[#94a3b8] transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            >
              analyst (Investigator)
            </button>
            <button
              type="button"
              onClick={() => setCredentials('viewer', 'Viewer123!')}
              className="rounded border border-[#334155] bg-[#1e293b] px-2.5 py-1 text-xs text-[#94a3b8] transition hover:border-[#22d3ee] hover:text-[#22d3ee]"
            >
              viewer (Audit)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;

import { useState, type FormEvent } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { Lock, User, AlertCircle, KeyRound } from 'lucide-react';

export function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(username, password);
      const token = localStorage.getItem('access_token') || `soc_session_${Date.now()}`;
      localStorage.setItem('soc_session_token', token);
      navigate('/');
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setError(axiosErr.response?.data?.detail || 'Invalid credentials.');
      } else {
        setError('Network error or platform server unreachable.');
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
    <div className="relative z-10 flex min-h-screen w-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-md border border-[#1f1f1f] bg-black/90 p-8 shadow-2xl backdrop-blur-md space-y-6">
        {/* Header / Brand with 4-Chevron Inward SVG Logo */}
        <div className="flex flex-col items-center text-center">
          <svg
            width="46"
            height="46"
            viewBox="0 0 46 46"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            className="mb-3"
          >
            <rect width="46" height="46" fill="#000000" stroke="#1f1f1f" strokeWidth="1" />
            <path d="M14 11L23 19L32 11" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
            <path d="M14 35L23 27L32 35" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
            <path d="M11 14L19 23L11 32" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
            <path d="M35 14L27 23L35 32" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
            <rect x="22" y="22" width="2" height="2" fill="#ffffff" />
          </svg>

          <h2 className="font-sg text-xl md:text-2xl font-bold uppercase tracking-wider text-white">
            Threat Attribution
          </h2>
          <p className="mt-1 font-jb text-xs uppercase tracking-widest text-[#949494]">
            Enterprise SOC Security Gateway
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="flex items-center gap-2 border border-[#c81b1c] bg-[#1a0505] p-3 font-jb text-xs text-[#c81b1c]">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 font-jb text-xs">
          <div>
            <label className="block uppercase text-[#949494] mb-1 font-sg tracking-wider">
              Operator Identity (Username)
            </label>
            <div className="relative">
              <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#949494]">
                <User className="h-3.5 w-3.5" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin or analyst"
                className="w-full bg-[#050505] border border-[#222222] py-2.5 pl-9 pr-3 text-white placeholder-[#555555]"
              />
            </div>
          </div>

          <div>
            <label className="block uppercase text-[#949494] mb-1 font-sg tracking-wider">
              Access Secret (Password)
            </label>
            <div className="relative">
              <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#949494]">
                <Lock className="h-3.5 w-3.5" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-[#050505] border border-[#222222] py-2.5 pl-9 pr-3 text-white placeholder-[#555555]"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="btn w-full justify-center mt-2"
          >
            {isSubmitting ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <span>Launch Console Access</span>
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
                  <path d="M6 3L11 8L6 13" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
                </svg>
              </>
            )}
          </button>
        </form>

        {/* Quick Fill Test Credentials */}
        <div className="border-t border-[#1a1a1a] pt-4 space-y-2">
          <div className="flex items-center gap-1.5 font-sg text-[10px] font-bold uppercase tracking-wider text-[#949494]">
            <KeyRound className="h-3 w-3 text-[#c81b1c]" />
            <span>Developer Test Accounts (Live DB)</span>
          </div>

          <div className="grid grid-cols-3 gap-1.5 font-jb text-[10px]">
            <button
              type="button"
              onClick={() => setCredentials('admin', 'admin123')}
              className="border border-[#222222] bg-[#0a0a0a] p-2 text-center text-[#949494] hover:border-[#c81b1c] hover:text-white"
            >
              <span className="block font-bold text-white uppercase">admin</span>
              <span className="text-[9px] text-[#949494]">Admin Role</span>
            </button>
            <button
              type="button"
              onClick={() => setCredentials('analyst', 'analyst123')}
              className="border border-[#222222] bg-[#0a0a0a] p-2 text-center text-[#949494] hover:border-[#c81b1c] hover:text-white"
            >
              <span className="block font-bold text-white uppercase">analyst</span>
              <span className="text-[9px] text-[#949494]">Analyst Role</span>
            </button>
            <button
              type="button"
              onClick={() => setCredentials('viewer', 'viewer123')}
              className="border border-[#222222] bg-[#0a0a0a] p-2 text-center text-[#949494] hover:border-[#c81b1c] hover:text-white"
            >
              <span className="block font-bold text-white uppercase">viewer</span>
              <span className="text-[9px] text-[#949494]">Read Only</span>
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center font-jb text-[10px] text-[#949494]">
          SECURE PROTOCOL · TLS / OAUTH2 JWT ENFORCED
        </div>
      </div>
    </div>
  );
}

export default LoginPage;

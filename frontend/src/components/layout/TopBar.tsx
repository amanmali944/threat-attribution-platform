import { useAuth } from '../../context/useAuth';
import { LogOut, Shield, User as UserIcon, Activity } from 'lucide-react';

export function TopBar() {
  const { user, logout } = useAuth();

  return (
    <header className="flex h-16 w-full items-center justify-between border-b border-[#334155] bg-[#0f172a]/80 px-6 backdrop-blur-md">
      {/* Left: Platform Title & System Operational Pill */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-[#22d3ee]" />
          <span className="font-mono text-base font-bold tracking-wider text-[#f1f5f9]">
            THREAT ATTRIBUTION PLATFORM
          </span>
        </div>
        <span className="hidden items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-400 sm:inline-flex">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          SOC LIVE
        </span>
      </div>

      {/* Right: Tenant, User Info & Logout Button */}
      <div className="flex items-center gap-4">
        {/* Tenant Pill */}
        <div className="hidden items-center gap-1.5 rounded border border-[#334155] bg-[#1e293b] px-2.5 py-1 text-xs text-[#94a3b8] md:flex">
          <Activity className="h-3.5 w-3.5 text-[#22d3ee]" />
          <span className="font-mono">TENANT:</span>
          <span className="font-mono font-semibold text-[#f1f5f9]">
            {user?.tenant_id || 'default_tenant'}
          </span>
        </div>

        {/* User Profile Pill */}
        <div className="flex items-center gap-2 rounded-lg border border-[#334155] bg-[#1e293b]/70 px-3 py-1.5 text-sm">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-[#334155] text-[#22d3ee]">
            <UserIcon className="h-3.5 w-3.5" />
          </div>
          <div className="flex flex-col text-left">
            <span className="text-xs font-semibold text-[#f1f5f9] leading-tight">
              {user?.username || 'Operator'}
            </span>
            <span className="text-[10px] font-mono uppercase text-[#22d3ee] leading-tight">
              {user?.role || 'Analyst'}
            </span>
          </div>
        </div>

        {/* Logout Button */}
        <button
          onClick={logout}
          title="Sign out of SOC console"
          className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 transition hover:bg-red-500/20 active:scale-95"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Logout</span>
        </button>
      </div>
    </header>
  );
}

export default TopBar;

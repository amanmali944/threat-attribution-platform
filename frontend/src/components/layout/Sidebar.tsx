import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  BellRing,
  ShieldAlert,
  Activity,
  Layers,
  Terminal,
} from 'lucide-react';

interface NavItem {
  name: string;
  to: string;
  icon: typeof LayoutDashboard;
  badge?: string;
}

const navItems: NavItem[] = [
  { name: 'Dashboard', to: '/', icon: LayoutDashboard },
  { name: 'Alerts', to: '/alerts', icon: BellRing },
  { name: 'Incidents', to: '/incidents', icon: ShieldAlert },
  { name: 'Platform Health', to: '/health', icon: Activity },
];

export function Sidebar() {
  return (
    <aside className="flex w-64 flex-col justify-between border-r border-[#334155] bg-[#0f172a] p-4">
      {/* Top Nav Section */}
      <div className="flex flex-col gap-6">
        {/* Navigation Category Label */}
        <div className="flex items-center gap-2 px-3 text-[11px] font-mono uppercase tracking-wider text-[#64748b]">
          <Layers className="h-3.5 w-3.5" />
          <span>SOC Navigation</span>
        </div>

        {/* Links List */}
        <nav className="flex flex-col gap-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                    isActive
                      ? 'border border-[#22d3ee]/30 bg-[#22d3ee]/10 text-[#22d3ee] shadow-[0_0_15px_rgba(34,211,238,0.15)]'
                      : 'text-[#94a3b8] hover:bg-[#1e293b] hover:text-[#f1f5f9]'
                  }`
                }
              >
                <div className="flex items-center gap-3">
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </div>
                {item.badge && (
                  <span className="rounded bg-[#334155] px-1.5 py-0.5 text-[10px] font-mono text-[#22d3ee]">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status / System Metadata Footer */}
      <div className="flex flex-col gap-3 rounded-lg border border-[#334155] bg-[#030712]/50 p-3 text-xs">
        <div className="flex items-center gap-2 text-[#94a3b8]">
          <Terminal className="h-4 w-4 text-[#22d3ee]" />
          <span className="font-mono text-[11px] font-semibold text-[#f1f5f9]">
            ATTRIBUTION CORE
          </span>
        </div>
        <div className="flex justify-between font-mono text-[10px] text-[#64748b]">
          <span>ENGINE VERSION:</span>
          <span className="text-[#22d3ee]">v1.0.0-PROD</span>
        </div>
        <div className="flex justify-between font-mono text-[10px] text-[#64748b]">
          <span>DEFENSE POSTURE:</span>
          <span className="text-emerald-400">OPTIMAL</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;

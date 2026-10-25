import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  BellRing,
  ShieldAlert,
  Activity,
  Layers,
  Terminal,
  BarChart3,
  Server,
} from 'lucide-react';

interface NavItem {
  name: string;
  to: string;
  icon: typeof LayoutDashboard;
  badge?: string;
}

const navItems: NavItem[] = [
  { name: 'Overview', to: '/', icon: LayoutDashboard },
  { name: 'Incidents', to: '/incidents', icon: ShieldAlert },
  { name: 'ML Evaluation', to: '/evaluation', icon: BarChart3, badge: 'BENCH' },
  { name: 'Entities', to: '/entities', icon: Server },
  { name: 'Alerts', to: '/alerts', icon: BellRing },
  { name: 'Platform Health', to: '/health', icon: Activity },
];

export function Sidebar() {
  return (
    <aside className="flex w-64 flex-col justify-between border-r border-[#1c1c1c] bg-black p-4">
      {/* Top Nav Section */}
      <div className="flex flex-col gap-6">
        <div className="flex items-center gap-2 px-2 text-[11px] font-jb uppercase tracking-wider text-[#949494]">
          <Layers className="h-3.5 w-3.5 text-[#c81b1c]" />
          <span>Console Navigation</span>
        </div>

        {/* Links List */}
        <nav className="flex flex-col gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 text-xs font-jb uppercase tracking-wider transition ${
                    isActive
                      ? 'border-l-2 border-[#c81b1c] bg-[#141414] text-white font-semibold'
                      : 'text-[#949494] hover:bg-[#0c0c0c] hover:text-white'
                  }`
                }
              >
                <div className="flex items-center gap-2.5">
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </div>
                {item.badge && (
                  <span className="border border-[#c81b1c] bg-[#c81b1c]/10 px-1 py-0.5 text-[9px] font-jb text-[#c81b1c]">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status / System Metadata Footer */}
      <div className="flex flex-col gap-2 border border-[#1f1f1f] bg-[#0a0a0a] p-3 text-xs">
        <div className="flex items-center gap-2 text-[#949494]">
          <Terminal className="h-3.5 w-3.5 text-[#c81b1c]" />
          <span className="font-sg text-[11px] font-bold text-white uppercase tracking-wider">
            Attribution Engine
          </span>
        </div>
        <div className="flex justify-between font-jb text-[10px] text-[#949494]">
          <span>VERSION:</span>
          <span className="text-white">v1.0.0-STAGE</span>
        </div>
        <div className="flex justify-between font-jb text-[10px] text-[#949494]">
          <span>POSTURE:</span>
          <span className="text-[#c81b1c] font-bold">OPERATIONAL</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;

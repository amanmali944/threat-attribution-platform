import { useState } from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/useAuth';
import { LogOut, Menu, X } from 'lucide-react';

export function TopBar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { label: 'Overview', path: '/' },
    { label: 'Incidents', path: '/incidents' },
    { label: 'Evaluation', path: '/evaluation' },
    { label: 'Entities', path: '/entities' },
    { label: 'Alerts', path: '/alerts' },
    { label: 'Health', path: '/health' },
  ];

  const handleLaunchSOC = () => {
    navigate('/incidents');
    setMobileMenuOpen(false);
  };

  return (
    <>
      <header className="relative z-30 flex h-16 w-full items-center justify-between border-b border-[#1c1c1c] bg-black/90 px-4 md:px-8 backdrop-blur-md">
        {/* Left: 4-Chevron Inward SVG Logo + Space Grotesk Title */}
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-3 group text-decoration-none">
            {/* 4-Chevron Inward SVG Logo (46x46) */}
            <svg
              width="46"
              height="46"
              viewBox="0 0 46 46"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              className="flex-shrink-0 transition-transform group-hover:scale-105"
            >
              <rect width="46" height="46" fill="#000000" stroke="#1f1f1f" strokeWidth="1" />
              {/* Top chevron pointing inward (down) */}
              <path d="M14 11L23 19L32 11" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
              {/* Bottom chevron pointing inward (up) */}
              <path d="M14 35L23 27L32 35" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
              {/* Left chevron pointing inward (right) */}
              <path d="M11 14L19 23L11 32" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
              {/* Right chevron pointing inward (left) */}
              <path d="M35 14L27 23L35 32" stroke="#c81b1c" strokeWidth="2.5" strokeLinecap="square" />
              {/* Center core target */}
              <rect x="22" y="22" width="2" height="2" fill="#ffffff" />
            </svg>

            <div className="flex flex-col">
              <span className="font-sg text-lg lg:text-xl font-bold tracking-wider text-white uppercase leading-none">
                Threat Attribution
              </span>
              <span className="text-xs tracking-widest text-[#94a3b8] uppercase leading-tight mt-1">
                Cross-Layer SOC Platform
              </span>
            </div>
          </Link>
        </div>

        {/* Center: Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1.5">
          {navLinks.map((link) => (
            <NavLink
              key={link.path}
              to={link.path}
              end={link.path === '/'}
              className={({ isActive }) =>
                `px-4 py-2 font-sg text-sm font-bold uppercase tracking-wider transition ${
                  isActive
                    ? 'border-b-2 border-[#c81b1c] text-white'
                    : 'text-[#94a3b8] hover:text-white hover:border-b-2 hover:border-[#475569]'
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>

        {/* Right: Sharp Launch SOC CTA + User Context + Mobile Burger */}
        <div className="flex items-center gap-3">
          {/* Tenant & User Info */}
          <div className="hidden xl:flex items-center gap-2 border border-[#262626] bg-[#0c0c0c] px-3.5 py-1.5 text-xs text-[#94a3b8]">
            <span className="text-[#94a3b8]">TENANT:</span>
            <span className="text-white font-mono font-semibold">{user?.tenant_id || 'DEFAULT'}</span>
            <span className="text-[#333333]">|</span>
            <span className="text-[#c81b1c] font-bold uppercase">{user?.role || 'ANALYST'}</span>
          </div>

          {/* Sharp Red "Launch SOC" CTA Button */}
          <button
            onClick={handleLaunchSOC}
            className="btn btn-sm hidden sm:inline-flex"
            title="Open Live Incident Investigation Workspace"
          >
            <span>Launch SOC</span>
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" className="transition-transform group-hover:translate-x-0.5">
              <path d="M6 3L11 8L6 13" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
            </svg>
          </button>

          {/* Sign Out Button */}
          <button
            onClick={() => {
              logout();
              localStorage.removeItem('soc_session_token');
              localStorage.removeItem('access_token');
              localStorage.removeItem('user');
              localStorage.clear();
              navigate('/login');
            }}
            title="Sign out of SOC console"
            className="btn btn-outline btn-sm inline-flex items-center gap-1.5 text-white border-[#333333] hover:border-[#c81b1c] hover:bg-[#1a0505]"
          >
            <LogOut className="h-3.5 w-3.5 text-[#c81b1c]" />
            <span className="font-bold tracking-wider uppercase text-xs">Sign Out</span>
          </button>

          {/* Mobile Burger Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="flex lg:hidden items-center justify-center border border-[#222222] bg-[#0a0a0a] p-2 text-white hover:border-[#c81b1c]"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="h-5 w-5 text-[#c81b1c]" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </header>

      {/* Mobile Burger Overlay Menu (#menu) with Animated Red Top Rule */}
      {mobileMenuOpen && (
        <div
          id="menu"
          className="fixed inset-0 top-16 z-40 flex flex-col justify-between border-b border-[#1c1c1c] bg-black/95 p-6 backdrop-blur-xl lg:hidden animate-fade-in"
        >
          {/* Animated Red Top Rule */}
          <div className="red-top-rule" />

          {/* Mobile Navigation List */}
          <div className="flex flex-col gap-4 mt-4">
            <span className="font-sg text-xs uppercase tracking-widest text-[#949494]">
              Navigation Directory
            </span>
            <div className="flex flex-col divide-y divide-[#1a1a1a]">
              {navLinks.map((link) => (
                <NavLink
                  key={link.path}
                  to={link.path}
                  end={link.path === '/'}
                  onClick={() => setMobileMenuOpen(false)}
                  className={({ isActive }) =>
                    `py-3 font-jb text-sm uppercase tracking-wider transition ${
                      isActive ? 'text-[#c81b1c] font-bold pl-2 border-l-2 border-[#c81b1c]' : 'text-white hover:text-[#c81b1c]'
                    }`
                  }
                >
                  {link.label}
                </NavLink>
              ))}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="flex flex-col gap-3 pt-6 border-t border-[#1c1c1c]">
            <button onClick={handleLaunchSOC} className="btn w-full justify-center">
              <span>Launch SOC Workspace</span>
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
                <path d="M6 3L11 8L6 13" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
              </svg>
            </button>
            <div className="flex items-center justify-between font-jb text-xs text-[#949494] px-1">
              <span>OPERATOR: {user?.username || 'ANALYST'}</span>
              <button
                onClick={() => {
                  logout();
                  localStorage.removeItem('soc_session_token');
                  localStorage.removeItem('access_token');
                  localStorage.removeItem('user');
                  localStorage.clear();
                  navigate('/login');
                }}
                className="text-[#c81b1c] font-bold hover:underline uppercase text-xs"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default TopBar;

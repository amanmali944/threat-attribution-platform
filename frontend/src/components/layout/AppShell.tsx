import { Outlet } from 'react-router-dom';
import { TopBar } from './TopBar';

export function AppShell() {
  return (
    <div className="relative z-10 flex min-h-screen w-full flex-col bg-black/75 text-white">
      {/* Top Header Navigation Shell */}
      <TopBar />

      {/* Main Stage Canvas with Responsive Scaling Grid */}
      <main className="flex-1 overflow-y-auto px-4 py-6 md:px-8 md:py-8">
        <div className="mx-auto max-w-[1505px] w-full">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

export default AppShell;

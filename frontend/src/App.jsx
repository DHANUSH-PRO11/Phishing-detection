import React, { useState } from 'react';
import Navbar from './components/Navbar';
import OverviewDashboard from './pages/OverviewDashboard';
import UrlScanner from './pages/UrlScanner';
import ScanDetails from './pages/ScanDetails';
import ScanHistory from './pages/ScanHistory';
import ModelInfo from './pages/ModelInfo';
import SettingsInfo from './pages/SettingsInfo';
import { ShieldAlert, Github, Heart } from 'lucide-react';

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [selectedScan, setSelectedScan] = useState(null);

  const handleSelectScan = (scanIdOrData) => {
    setSelectedScan(scanIdOrData);
    setActivePage('details');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleScanComplete = (scanResponse) => {
    setSelectedScan(scanResponse);
  };

  return (
    <div className="min-h-screen bg-cyber-950 text-slate-100 flex flex-col font-sans selection:bg-red-500/30 selection:text-white">
      {/* Top Navigation */}
      <Navbar
        activePage={activePage}
        setActivePage={(page) => {
          setActivePage(page);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activePage === 'dashboard' && (
          <OverviewDashboard
            onNavigateToScanner={() => setActivePage('scanner')}
            onSelectScan={handleSelectScan}
          />
        )}

        {activePage === 'scanner' && (
          <UrlScanner
            onScanComplete={handleScanComplete}
            onViewDetails={handleSelectScan}
          />
        )}

        {activePage === 'details' && (
          <ScanDetails
            scanIdOrData={selectedScan}
            onBack={() => setActivePage('history')}
          />
        )}

        {activePage === 'history' && (
          <ScanHistory
            onSelectScan={handleSelectScan}
            onNavigateToScanner={() => setActivePage('scanner')}
          />
        )}

        {activePage === 'model' && <ModelInfo />}

        {activePage === 'settings' && <SettingsInfo />}
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 bg-cyber-900/60 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            <span className="font-semibold text-slate-400">PhishShield Cybersecurity Lab</span>
            <span>&bull;</span>
            <span>Offline ML URL Threat Classification</span>
          </div>

          <div className="text-slate-500 text-center sm:text-right">
            Defensive Cybersecurity Platform &bull; No Target Navigation Executed
          </div>
        </div>
      </footer>
    </div>
  );
}

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import ThreatList from './components/ThreatList';
import AgentStatus from './components/AgentStatus';
import NetworkMap from './components/NetworkMap';
import AttackTimeline from './components/AttackTimeline';
import ThreatIntel from './components/ThreatIntel';

function Layout({ children }) {
  return (
    <div className="flex h-screen bg-dark-bg text-gray-100 overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout><Dashboard /></Layout>} />
        <Route path="/threats" element={<Layout><ThreatList /></Layout>} />
        <Route path="/agents" element={<Layout><AgentStatus /></Layout>} />
        <Route path="/network" element={<Layout><NetworkMap /></Layout>} />
        <Route path="/timeline" element={<Layout><AttackTimeline /></Layout>} />
        <Route path="/intel" element={<Layout><ThreatIntel /></Layout>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

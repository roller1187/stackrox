import { Routes, Route, Navigate } from 'react-router-dom-v5-compat';

import LandingPage from './LandingPage';
import ReportPage from './ReportPage';

export default function CveAnalyzerPage() {
  return (
    <Routes>
      <Route index element={<LandingPage />} />
      <Route path="reports/:id" element={<ReportPage />} />
      <Route path="settings" element={<Navigate to="/main/systemconfig#cve-analyzer-config" replace />} />
      <Route path="*" element={<Navigate to="" replace />} />
    </Routes>
  );
}

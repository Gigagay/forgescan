import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider, createTheme } from '@mui/material';
import CssBaseline from '@mui/material/CssBaseline';

import { useAuth } from '@/hooks/useAuth';
import { useWebSocket } from '@/hooks/useWebSocket';

// Pages
import { LandingPage } from '@/pages/Landing';
import { LoginPage } from '@/pages/Login';
import { SignupPage } from '@/pages/Signup';
import { DashboardPage } from '@/pages/Dashboard';
import { ScansPage } from '@/pages/Scans';
import { ScanDetailPage } from '@/pages/ScanDetail';
import { BillingPage } from '@/pages/Billing';
import { AppLayout } from '@/components/layout/AppLayout';
import { Loading } from '@/components/common/Loading';
import { PricingPage } from '@/pages/Pricing';
import { CheckoutPage } from '@/pages/CheckoutPage';
import { BillingSuccessPage } from '@/pages/BillingSuccess';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

const theme = createTheme({
  palette: {
    primary: {
      main: '#667eea',
    },
    secondary: {
      main: '#764ba2',
    },
    error: {
      main: '#d32f2f',
    },
    warning: {
      main: '#f57c00',
    },
    info: {
      main: '#1976d2',
    },
    success: {
      main: '#388e3c',
    },
  },
  typography: {
    fontFamily: [
      '-apple-system',
      'BlinkMacSystemFont',
      '"Segoe UI"',
      'Roboto',
      '"Helvetica Neue"',
      'Arial',
      'sans-serif',
    ].join(','),
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
        },
      },
    },
  },
});

const PrivateRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <Loading />;
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
};

const AuthenticatedApp: React.FC = () => {
  useWebSocket(); // Initialize WebSocket connection

  return (
    <Routes>
      <Route path="/" element={<AppLayout />}>
        <Route index element={<Navigate to="/dashboard" />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/:scanId" element={<ScanDetailPage />} />
        <Route path="billing" element={<BillingPage />} />
        <Route path="/pricing" element={<PricingPage />} />
        <Route path="/billing/checkout" element={<CheckoutPage />} />
        <Route path="/billing/success" element={<BillingSuccessPage />} />
      </Route>
    </Routes>
  );
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />

            {/* Protected routes */}
            <Route
              path="/*"
              element={
                <PrivateRoute>
                  <AuthenticatedApp />
                </PrivateRoute>
              }
            />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;

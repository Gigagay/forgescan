// frontend/src/pages/Dashboard.tsx
import React from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  LinearProgress,
} from '@mui/material';
import {
  TrendingUp,
  Security,
  BugReport,
  Speed,
  Add,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { scansAPI } from '@/api/scans';
import { format } from 'date-fns';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scansAPI.list,
  });

  // Calculate statistics
  const stats = React.useMemo(() => {
    if (!scans) return null;

    const totalScans = scans.length;
    const completedScans = scans.filter((s) => s.status === 'completed').length;
    const totalFindings = scans.reduce(
      (sum, s) => sum + (s.findings_summary?.total_findings || 0),
      0
    );
    const criticalFindings = scans.reduce(
      (sum, s) => sum + (s.findings_summary?.critical_count || 0),
      0
    );
    const avgRiskScore =
      scans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / completedScans || 0;

    return {
      totalScans,
      completedScans,
      totalFindings,
      criticalFindings,
      avgRiskScore: avgRiskScore.toFixed(1),
    };
  }, [scans]);

  // Prepare chart data
  const riskTrendData = React.useMemo(() => {
    if (!scans) return [];

    return scans
      .filter((s) => s.status === 'completed' && s.risk_score)
      .slice(-7)
      .map((s) => ({
        date: format(new Date(s.created_at), 'MM/dd'),
        riskScore: s.risk_score,
      }));
  }, [scans]);

  const severityData = React.useMemo(() => {
    if (!scans) return [];

    const totals = scans.reduce(
      (acc, s) => {
        if (s.findings_summary) {
          acc.critical += s.findings_summary.critical_count || 0;
          acc.high += s.findings_summary.high_count || 0;
          acc.medium += s.findings_summary.medium_count || 0;
          acc.low += s.findings_summary.low_count || 0;
        }
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );

    return [
      { name: 'Critical', value: totals.critical, color: '#d32f2f' },
      { name: 'High', value: totals.high, color: '#f57c00' },
      { name: 'Medium', value: totals.medium, color: '#fbc02d' },
      { name: 'Low', value: totals.low, color: '#388e3c' },
    ].filter((item) => item.value > 0);
  }, [scans]);

  const recentScans = scans?.slice(0, 5) || [];

  if (isLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 4 }}>
        <Typography variant="h4" component="h1" fontWeight="bold">
          Security Dashboard
        </Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => navigate('/scans/new')}
        >
          New Scan
        </Button>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Security sx={{ mr: 1, color: 'primary.main' }} />
                <Typography color="text.secondary" variant="body2">
                  Total Scans
                </Typography>
              </Box>
              <Typography variant="h4" fontWeight="bold">
                {stats?.totalScans || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stats?.completedScans || 0} completed
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <BugReport sx={{ mr: 1, color: 'error.main' }} />
                <Typography color="text.secondary" variant="body2">
                  Findings
                </Typography>
              </Box>
              <Typography variant="h4" fontWeight="bold">
                {stats?.totalFindings || 0}
              </Typography>
              <Typography variant="body2" color="error.main">
                {stats?.criticalFindings || 0} critical
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TrendingUp sx={{ mr: 1, color: 'warning.main' }} />
                <Typography color="text.secondary" variant="body2">
                  Avg Risk Score
                </Typography>
              </Box>
              <Typography variant="h4" fontWeight="bold">
                {stats?.avgRiskScore || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                out of 100
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Speed sx={{ mr: 1, color: 'success.main' }} />
                <Typography color="text.secondary" variant="body2">
                  This Month
                </Typography>
              </Box>
              <Typography variant="h4" fontWeight="bold">
                {stats?.totalScans || 0}
              </Typography>
              <Typography variant="body2" color="success.main">
                ↑ Active monitoring
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Risk Score Trend
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={riskTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="riskScore"
                  stroke="#1976d2"
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Findings by Severity
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* Recent Scans */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6">Recent Scans</Typography>
          <Button variant="text" onClick={() => navigate('/scans')}>
            View All
          </Button>
        </Box>

        {recentScans.map((scan) => (
          <Box
            key={scan.id}
            sx={{
              display: 'flex',
              alignItems: 'center',
              p: 2,
              mb: 1,
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 1,
              cursor: 'pointer',
              '&:hover': { bgcolor: 'action.hover' },
            }}
            onClick={() => navigate(`/scans/${scan.id}`)}
          >
            <Box sx={{ flexGrow: 1 }}>
              <Typography variant="body1" fontWeight="medium">
                {scan.target}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
              </Typography>
            </Box>

            <Chip
              label={scan.scanner_type.toUpperCase()}
              size="small"
              sx={{ mr: 2 }}
            />

            <Chip
              label={scan.status}
              color={
                scan.status === 'completed'
                  ? 'success'
                  : scan.status === 'running'
                  ? 'primary'
                  : scan.status === 'failed'
                  ? 'error'
                  : 'default'
              }
              size="small"
              sx={{ mr: 2 }}
            />

            {scan.findings_summary && (
              <Box sx={{ display: 'flex', gap: 1 }}>
                {scan.findings_summary.critical_count > 0 && (
                  <Chip
                    label={`${scan.findings_summary.critical_count} Critical`}
                    color="error"
                    size="small"
                  />
                )}
                {scan.findings_summary.high_count > 0 && (
                  <Chip
                    label={`${scan.findings_summary.high_count} High`}
                    color="warning"
                    size="small"
                  />
                )}
              </Box>
            )}
          </Box>
        ))}

        {recentScans.length === 0 && (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography color="text.secondary">No scans yet</Typography>
            <Button
              variant="contained"
              sx={{ mt: 2 }}
              onClick={() => navigate('/scans/new')}
            >
              Run Your First Scan
            </Button>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

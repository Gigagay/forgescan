// frontend/src/pages/ExecutiveDashboard.tsx
/**
 * Executive Dashboard - C-Level Security Overview
 * Provides high-level metrics, trends, and compliance status
 */

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Alert,
  Chip,
  LinearProgress
} from '@mui/material';
import {
  TrendingUp,
  TrendingDown,
  AlertCircle,
  Shield,
  Download,
  Clock
} from 'lucide-react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import { api } from '../services/api';

// Color palette
const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#3b82f6'
};


interface DashboardData {
  security_posture_score: number;
  trend: string;
  critical_issues: number;
  high_issues: number;
  total_open_findings: number;
  mean_time_to_remediate: string;
  compliance_status: {
    OWASP_Top_10: string;
    PCI_DSS: string;
    SOC2: string;
  };
  risk_by_category: Array<{
    category: string;
    count: number;
    severity: string;
  }>;
  timeline: Array<{
    date: string;
    score: number;
  }>;
  top_vulnerabilities: Array<{
    title: string;
    severity: string;
    count: number;
  }>;
}

export const ExecutiveDashboard: React.FC = () => {
  const [dateRange, setDateRange] = useState(30);

  const { data, isLoading, error } = useQuery<DashboardData>({
    queryKey: ['executive-dashboard', dateRange],
    queryFn: () => api.get(`/api/v1/executive/dashboard?date_range=${dateRange}`),
    refetchInterval: 300000 // Refresh every 5 minutes
  });

  const handleExport = async () => {
    const response = await api.get(
      `/api/v1/executive/dashboard/export?date_range=${dateRange}&format=csv`,
      { responseType: 'blob' }
    );
    
    const url = window.URL.createObjectURL(new Blob([response]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `executive_report_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error">
        Failed to load executive dashboard. Please try again.
      </Alert>
    );
  }

  if (!data) return null;

  const trendIsPositive = data.trend.startsWith('+');

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Executive Security Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Security posture and compliance overview
          </Typography>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Time Period</InputLabel>
            <Select
              value={dateRange}
              label="Time Period"
              onChange={(e) => setDateRange(Number(e.target.value))}
            >
              <MenuItem value={7}>Last 7 days</MenuItem>
              <MenuItem value={30}>Last 30 days</MenuItem>
              <MenuItem value={90}>Last 90 days</MenuItem>
              <MenuItem value={180}>Last 6 months</MenuItem>
            </Select>
          </FormControl>
          
          <Button
            variant="outlined"
            startIcon={<Download size={18} />}
            onClick={handleExport}
          >
            Export Report
          </Button>
        </Box>
      </Box>

      {/* Key Metrics */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Security Posture Score */}
        <Grid item xs={12} md={3}>
          <Card sx={{ height: '100%', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Shield size={24} color="white" />
                <Typography variant="subtitle2" sx={{ ml: 1, color: 'white' }}>
                  Security Posture
                </Typography>
              </Box>
              
              <Typography variant="h2" fontWeight="bold" sx={{ color: 'white' }}>
                {data.security_posture_score}
              </Typography>
              
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                {trendIsPositive ? (
                  <TrendingUp size={18} color="white" />
                ) : (
                  <TrendingDown size={18} color="white" />
                )}
                <Typography variant="body2" sx={{ ml: 1, color: 'white' }}>
                  {data.trend} from last period
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Critical Issues */}
        <Grid item xs={12} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <AlertCircle size={24} color={COLORS.critical} />
                <Typography variant="subtitle2" sx={{ ml: 1 }}>
                  Critical Issues
                </Typography>
              </Box>
              
              <Typography variant="h2" fontWeight="bold">
                {data.critical_issues}
              </Typography>
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Require immediate attention
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* High Issues */}
        <Grid item xs={12} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <AlertCircle size={24} color={COLORS.high} />
                <Typography variant="subtitle2" sx={{ ml: 1 }}>
                  High Priority
                </Typography>
              </Box>
              
              <Typography variant="h2" fontWeight="bold">
                {data.high_issues}
              </Typography>
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Address within 30 days
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* MTTR */}
        <Grid item xs={12} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Clock size={24} color={COLORS.info} />
                <Typography variant="subtitle2" sx={{ ml: 1 }}>
                  Mean Time to Fix
                </Typography>
              </Box>
              
              <Typography variant="h2" fontWeight="bold">
                {data.mean_time_to_remediate}
              </Typography>
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Average remediation time
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Compliance Status */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight="bold" sx={{ mb: 3 }}>
                Compliance Status
              </Typography>
              
              <Grid container spacing={3}>
                {Object.entries(data.compliance_status).map(([framework, score]) => {
                  const scoreNum = parseInt(score);
                  const color = scoreNum >= 90 ? 'success' : scoreNum >= 70 ? 'warning' : 'error';
                  
                  return (
                    <Grid item xs={12} md={4} key={framework}>
                      <Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                          <Typography variant="subtitle2">
                            {framework.replace(/_/g, ' ')}
                          </Typography>
                          <Typography variant="subtitle2" fontWeight="bold">
                            {score}
                          </Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={scoreNum}
                          color={color}
                          sx={{ height: 8, borderRadius: 4 }}
                        />
                      </Box>
                    </Grid>
                  );
                })}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Security Trend */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight="bold" sx={{ mb: 2 }}>
                Security Posture Trend
              </Typography>
              
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={data.timeline}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(date) => new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                  />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#667eea"
                    strokeWidth={3}
                    dot={{ fill: '#667eea', r: 4 }}
                    name="Security Score"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Top Vulnerabilities */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" fontWeight="bold" sx={{ mb: 2 }}>
                Top Vulnerabilities
              </Typography>
              
              <Box>
                {data.top_vulnerabilities.map((vuln, idx) => (
                  <Box
                    key={idx}
                    sx={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      mb: 2,
                      p: 1,
                      borderRadius: 1,
                      bgcolor: 'grey.50'
                    }}
                  >
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="body2" fontWeight="medium">
                        {vuln.title}
                      </Typography>
                      <Chip
                        label={vuln.severity}
                        size="small"
                        sx={{
                          mt: 0.5,
                          bgcolor: COLORS[vuln.severity as keyof typeof COLORS],
                          color: 'white',
                          fontSize: '0.7rem'
                        }}
                      />
                    </Box>
                    <Typography variant="h6" fontWeight="bold">
                      {vuln.count}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Risk by Category */}
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" fontWeight="bold" sx={{ mb: 2 }}>
                Risk Distribution by Category
              </Typography>
              
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={data.risk_by_category}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="category" angle={-45} textAnchor="end" height={100} />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="count" name="Findings">
                    {data.risk_by_category.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={COLORS[entry.severity as keyof typeof COLORS]}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Executive Summary Alert */}
      {data.critical_issues > 0 && (
        <Alert severity="error" sx={{ mt: 3 }}>
          <Typography variant="subtitle2" fontWeight="bold">
            Action Required
          </Typography>
          <Typography variant="body2">
            {data.critical_issues} critical security {data.critical_issues === 1 ? 'issue' : 'issues'} require immediate attention.
            Review the findings and assign them to your security team.
          </Typography>
        </Alert>
      )}
    </Box>
  );
};
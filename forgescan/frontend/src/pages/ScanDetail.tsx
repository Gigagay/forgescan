// frontend/src/pages/ScanDetail.tsx
import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Grid,
  Chip,
  Tab,
  Tabs,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Collapse,
  IconButton,
  Alert,
  LinearProgress,
} from '@mui/material';
import {
  ArrowBack,
  Download,
  KeyboardArrowDown,
  KeyboardArrowUp,
  CheckCircle,
  Error,
  Warning,
  Info,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { scansAPI } from '@/api/scans';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
  </div>
);

const FindingRow: React.FC<{ finding: any }> = ({ finding }) => {
  const [open, setOpen] = useState(false);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <Error color="error" />;
      case 'high':
        return <Warning color="warning" />;
      case 'medium':
        return <Info color="info" />;
      case 'low':
        return <CheckCircle color="success" />;
      default:
        return <Info />;
    }
  };

  return (
    <>
      <TableRow sx={{ '& > *': { borderBottom: 'unset' } }}>
        <TableCell>
          <IconButton size="small" onClick={() => setOpen(!open)}>
            {open ? <KeyboardArrowUp /> : <KeyboardArrowDown />}
          </IconButton>
        </TableCell>
        <TableCell>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {getSeverityIcon(finding.severity)}
            <Chip
              label={finding.severity}
              color={
                finding.severity === 'critical'
                  ? 'error'
                  : finding.severity === 'high'
                  ? 'warning'
                  : finding.severity === 'medium'
                  ? 'info'
                  : 'success'
              }
              size="small"
            />
          </Box>
        </TableCell>
        <TableCell>
          <Typography variant="body2" fontWeight="medium">
            {finding.title}
          </Typography>
          {finding.url && (
            <Typography variant="caption" color="text.secondary">
              {finding.url}
            </Typography>
          )}
        </TableCell>
        <TableCell>
          {finding.owasp_category && (
            <Chip label={finding.owasp_category} size="small" variant="outlined" />
          )}
        </TableCell>
        <TableCell>
          {finding.cwe_id && (
            <Chip label={finding.cwe_id} size="small" variant="outlined" />
          )}
        </TableCell>
        <TableCell>
          <Chip
            label={finding.status}
            color={finding.status === 'open' ? 'error' : 'success'}
            size="small"
          />
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            <Box sx={{ margin: 2 }}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>
                    Description
                  </Typography>
                  <Typography variant="body2" paragraph>
                    {finding.description}
                  </Typography>
                </Grid>

                {finding.evidence && (
                  <Grid item xs={12}>
                    <Typography variant="h6" gutterBottom>
                      Evidence
                    </Typography>
                    <Paper sx={{ p: 2, bgcolor: 'grey.100' }}>
                      <Typography variant="body2" component="pre" sx={{ fontFamily: 'monospace' }}>
                        {finding.evidence}
                      </Typography>
                    </Paper>
                  </Grid>
                )}

                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>
                    Remediation
                  </Typography>
                  <Alert severity="info">
                    {finding.remediation || 'No remediation guidance available'}
                  </Alert>
                </Grid>

                {finding.references && finding.references.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="h6" gutterBottom>
                      References
                    </Typography>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      {finding.references.map((ref: string, idx: number) => (
                        <Button
                          key={idx}
                          href={ref}
                          target="_blank"
                          variant="outlined"
                          size="small"
                          sx={{ justifyContent: 'flex-start' }}
                        >
                          {ref}
                        </Button>
                      ))}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
};

export const ScanDetailPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansAPI.get(scanId!),
    enabled: !!scanId,
    refetchInterval: (data) => {
      // Stop refetching if scan is completed or failed
      return (data as any)?.status === 'running' || (data as any)?.status === 'pending' ? 3000 : false;
    },
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => scansAPI.getFindings(scanId!),
    enabled: !!scanId && scan?.status === 'completed',
  });

  if (scanLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
      </Box>
    );
  }

  if (!scan) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4 }}>
        <Alert severity="error">Scan not found</Alert>
      </Container>
    );
  }

  const handleExportPDF = () => {
    // TODO: Implement PDF export
    alert('PDF export will be implemented');
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
        <IconButton onClick={() => navigate('/scans')} sx={{ mr: 2 }}>
          <ArrowBack />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h4" component="h1" fontWeight="bold">
            {scan.target}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {format(new Date(scan.created_at), 'MMM dd, yyyy HH:mm')}
          </Typography>
        </Box>
        <Button variant="outlined" startIcon={<Download />} onClick={handleExportPDF}>
          Export PDF
        </Button>
      </Box>

      {/* Status Alert */}
      {scan.status === 'running' && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Scan in progress... {scan.progress}% complete
          <LinearProgress variant="determinate" value={scan.progress} sx={{ mt: 1 }} />
        </Alert>
      )}

      {scan.status === 'failed' && (
        <Alert severity="error" sx={{ mb: 3 }}>
          Scan failed: {scan.error_message || 'Unknown error'}
        </Alert>
      )}

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" variant="body2" gutterBottom>
                Scanner Type
              </Typography>
              <Chip label={scan.scanner_type.toUpperCase()} color="primary" />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" variant="body2" gutterBottom>
                Status
              </Typography>
              <Chip
                label={scan.status}
                color={
                  scan.status === 'completed'
                    ? 'success'
                    : scan.status === 'failed'
                    ? 'error'
                    : 'primary'
                }
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" variant="body2" gutterBottom>
                Total Findings
              </Typography>
              <Typography variant="h4" fontWeight="bold">
                {scan.findings_summary?.total_findings || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" variant="body2" gutterBottom>
                Risk Score
              </Typography>
              <Typography variant="h4" fontWeight="bold">
                {scan.risk_score?.toFixed(0) || '-'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Findings Breakdown */}
      {scan.findings_summary && (
        <Paper sx={{ p: 3, mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            Findings Breakdown
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={2.4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="error.main" fontWeight="bold">
                  {scan.findings_summary.critical_count || 0}
                </Typography>
                <Typography color="text.secondary">Critical</Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={2.4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="warning.main" fontWeight="bold">
                  {scan.findings_summary.high_count || 0}
                </Typography>
                <Typography color="text.secondary">High</Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={2.4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="info.main" fontWeight="bold">
                  {scan.findings_summary.medium_count || 0}
                </Typography>
                <Typography color="text.secondary">Medium</Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={2.4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" color="success.main" fontWeight="bold">
                  {scan.findings_summary.low_count || 0}
                </Typography>
                <Typography color="text.secondary">Low</Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={2.4}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h3" fontWeight="bold">
                  {scan.findings_summary.info_count || 0}
                </Typography>
                <Typography color="text.secondary">Info</Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>
      )}

      {/* Tabs */}
      <Paper>
        <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)}>
          <Tab label="Findings" />
          <Tab label="Details" />
        </Tabs>

        <TabPanel value={tabValue} index={0}>
          {findingsLoading ? (
            <LinearProgress />
          ) : findings && findings.length > 0 ? (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell width={50} />
                    <TableCell>Severity</TableCell>
                    <TableCell>Finding</TableCell>
                    <TableCell>OWASP</TableCell>
                    <TableCell>CWE</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findings.map((finding) => (
                    <FindingRow key={finding.id} finding={finding} />
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography color="text.secondary">
                {scan.status === 'completed'
                  ? 'No findings detected'
                  : 'Findings will appear when scan completes'}
              </Typography>
            </Box>
          )}
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Scan ID
              </Typography>
              <Typography variant="body1" paragraph>
                {scan.id}
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Target URL
              </Typography>
              <Typography variant="body1" paragraph>
                {scan.target}
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Started At
              </Typography>
              <Typography variant="body1" paragraph>
                {scan.started_at
                  ? format(new Date(scan.started_at), 'MMM dd, yyyy HH:mm:ss')
                  : '-'}
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Completed At
              </Typography>
              <Typography variant="body1" paragraph>
                {scan.completed_at
                  ? format(new Date(scan.completed_at), 'MMM dd, yyyy HH:mm:ss')
                  : '-'}
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Duration
              </Typography>
              <Typography variant="body1" paragraph>
                {scan.duration_seconds
                  ? `${Math.floor(scan.duration_seconds / 60)}m ${scan.duration_seconds % 60}s`
                  : '-'}
              </Typography>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>
    </Container>
  );
};


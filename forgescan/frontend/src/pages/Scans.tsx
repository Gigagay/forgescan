// frontend/src/pages/Scans.tsx
import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  LinearProgress,
} from '@mui/material';
import {
  Add,
  Delete,
  Visibility,
  Refresh,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { format } from 'date-fns';
import { scansAPI } from '@/api/scans';

export const ScansPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [openDialog, setOpenDialog] = useState(false);
  const [newScan, setNewScan] = useState({
    scanner_type: 'web' as 'web' | 'api',
    target: '',
    options: {},
  });

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: scansAPI.list,
    refetchInterval: 5000, // Refetch every 5 seconds for real-time updates
  });

  const createMutation = useMutation({
    mutationFn: scansAPI.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setOpenDialog(false);
      setNewScan({ scanner_type: 'web', target: '', options: {} });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: scansAPI.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const handleCreateScan = () => {
    if (!newScan.target) return;
    createMutation.mutate(newScan);
  };

  const handleDeleteScan = (id: string) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      deleteMutation.mutate(id);
    }
  };


  if (isLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 4 }}>
        <Typography variant="h4" component="h1" fontWeight="bold">
          Security Scans
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={() => queryClient.invalidateQueries({ queryKey: ['scans'] })}
            sx={{ mr: 2 }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => setOpenDialog(true)}
          >
            New Scan
          </Button>
        </Box>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Target</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Findings</TableCell>
              <TableCell>Risk Score</TableCell>
              <TableCell>Created</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {scans?.map((scan) => (
              <TableRow key={scan.id} hover>
                <TableCell>
                  <Typography variant="body2" fontWeight="medium">
                    {scan.target}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={scan.scanner_type.toUpperCase()}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>
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
                  />
                  {scan.status === 'running' && (
                    <Box sx={{ width: '100%', mt: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={scan.progress}
                      />
                    </Box>
                  )}
                </TableCell>
                <TableCell>
                  {scan.findings_summary ? (
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {scan.findings_summary.critical_count > 0 && (
                        <Chip
                          label={`${scan.findings_summary.critical_count}C`}
                          color="error"
                          size="small"
                        />
                      )}
                      {scan.findings_summary.high_count > 0 && (
                        <Chip
                          label={`${scan.findings_summary.high_count}H`}
                          color="warning"
                          size="small"
                        />
                      )}
                      {scan.findings_summary.medium_count > 0 && (
                        <Chip
                          label={`${scan.findings_summary.medium_count}M`}
                          color="info"
                          size="small"
                        />
                      )}
                      {scan.findings_summary.low_count > 0 && (
                        <Chip
                          label={`${scan.findings_summary.low_count}L`}
                          color="success"
                          size="small"
                        />
                      )}
                    </Box>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  {scan.risk_score ? (
                    <Chip
                      label={scan.risk_score.toFixed(0)}
                      color={
                        scan.risk_score >= 70
                          ? 'error'
                          : scan.risk_score >= 40
                          ? 'warning'
                          : 'success'
                      }
                      size="small"
                    />
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {format(new Date(scan.created_at), 'MMM dd, yyyy')}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {format(new Date(scan.created_at), 'HH:mm')}
                  </Typography>
                </TableCell>
                <TableCell align="right">
                  <IconButton
                    size="small"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                  >
                    <Visibility />
                  </IconButton>
                  <IconButton
                    size="small"
                    onClick={() => handleDeleteScan(scan.id)}
                  >
                    <Delete />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create Scan Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Scan</DialogTitle>
        <DialogContent>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Scanner Type</InputLabel>
            <Select
              value={newScan.scanner_type}
              onChange={(e) =>
                setNewScan({
                  ...newScan,
                  scanner_type: e.target.value as 'web' | 'api',
                })
              }
            >
              <MenuItem value="web">Web Application</MenuItem>
              <MenuItem value="api">API Endpoint</MenuItem>
            </Select>
          </FormControl>

          <TextField
            fullWidth
            label="Target URL"
            value={newScan.target}
            onChange={(e) => setNewScan({ ...newScan, target: e.target.value })}
            margin="normal"
            placeholder="https://example.com"
            helperText="Enter the URL you want to scan"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button
            onClick={handleCreateScan}
            variant="contained"
            disabled={!newScan.target || createMutation.isPending}
          >
            {createMutation.isPending ? 'Creating...' : 'Start Scan'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};
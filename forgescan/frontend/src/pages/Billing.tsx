// frontend/src/pages/Billing.tsx
import React from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Paper,
  Grid,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import { TrendingUp, Cancel } from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { billingAPI } from '@/api/billing';

export const BillingPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [cancelDialogOpen, setCancelDialogOpen] = React.useState(false);

  const { data: usage } = useQuery({
    queryKey: ['billing-usage'],
    queryFn: billingAPI.getUsage,
  });

  const cancelMutation = useMutation({
    mutationFn: billingAPI.cancelSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['billing-usage'] });
      setCancelDialogOpen(false);
    },
  });

  const handleCancelSubscription = () => {
    cancelMutation.mutate();
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom fontWeight="bold">
        Billing & Usage
      </Typography>

      {/* Current Plan */}
      <Paper sx={{ p: 3, mb: 4 }}>
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} md={6}>
            <Typography variant="h6" gutterBottom>
              Current Plan
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Chip
                label={usage?.current_plan?.toUpperCase()}
                color="primary"
                size="medium"
              />
              {usage?.subscription_status && (
                <Chip
                  label={usage.subscription_status}
                  color={
                    usage.subscription_status === 'active'
                      ? 'success'
                      : usage.subscription_status === 'cancelled'
                      ? 'error'
                      : 'default'
                  }
                  size="small"
                />
              )}
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {usage?.current_plan === 'free'
                ? 'Upgrade to unlock more scans and features'
                : 'Thank you for being a paying customer!'}
            </Typography>
          </Grid>
          <Grid item xs={12} md={6} sx={{ textAlign: 'right' }}>
            {usage?.current_plan !== 'free' ? (
              <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<Cancel />}
                  onClick={() => setCancelDialogOpen(true)}
                >
                  Cancel Subscription
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<TrendingUp />}
                  onClick={() => navigate('/pricing')}
                >
                  Change Plan
                </Button>
              </Box>
            ) : (
              <Button
                variant="contained"
                startIcon={<TrendingUp />}
                onClick={() => navigate('/pricing')}
              >
                Upgrade Now
              </Button>
            )}
          </Grid>
        </Grid>
      </Paper>

      {/* Payment Methods Info */}
      {usage?.current_plan !== 'free' && (
        <Alert severity="info" sx={{ mb: 4 }}>
          <Typography variant="body2">
            Your subscription is managed through Peach Payments. For billing inquiries,
            please contact support@forgescan.io
          </Typography>
        </Alert>
      )}

      {/* Usage Stats - Same as before */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scans This Month
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'baseline', mb: 2 }}>
                <Typography variant="h3" fontWeight="bold">
                  {usage?.usage?.scans_this_month || 0}
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ ml: 1 }}>
                  / {usage?.limits?.max_scans_per_month || 0}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={
                  ((usage?.usage?.scans_this_month || 0) /
                    (usage?.limits?.max_scans_per_month || 1)) *
                  100
                }
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {usage?.scans_remaining || 0} scans remaining
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Users
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'baseline', mb: 2 }}>
                <Typography variant="h3" fontWeight="bold">
                  {usage?.usage?.users_count || 0}
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ ml: 1 }}>
                  / {usage?.limits?.max_users || 0}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={
                  ((usage?.usage?.users_count || 0) / (usage?.limits?.max_users || 1)) *
                  100
                }
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Cancel Confirmation Dialog */}
      <Dialog open={cancelDialogOpen} onClose={() => setCancelDialogOpen(false)}>
        <DialogTitle>Cancel Subscription</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to cancel your subscription? You will be downgraded to
            the Free plan at the end of your billing period.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCancelDialogOpen(false)}>Keep Subscription</Button>
          <Button
            onClick={handleCancelSubscription}
            color="error"
            variant="contained"
            disabled={cancelMutation.isPending}
          >
            {cancelMutation.isPending ? 'Cancelling...' : 'Cancel Subscription'}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

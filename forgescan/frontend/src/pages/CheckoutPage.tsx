// frontend/src/pages/CheckoutPage.tsx 
import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  CircularProgress,
  Alert,
  Button,
} from '@mui/material';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { billingAPI } from '@/api/billing';

export const CheckoutPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const plan = searchParams.get('plan');
  const period = searchParams.get('period') as 'monthly' | 'yearly';
  const currency = searchParams.get('currency') || 'USD';
  const checkoutId = searchParams.get('id'); // For returning from payment

  useEffect(() => {
    const initCheckout = async () => {
      try {
        if (checkoutId) {
          // Check payment status
          const status = await billingAPI.getCheckoutStatus(checkoutId);
          
          if (status.success) {
            // Payment successful, redirect to success page
            navigate('/billing/success');
          } else {
            setError('Payment failed: ' + status.description);
            setLoading(false);
          }
        } else if (plan && period) {
          // Create new checkout
          const response = await billingAPI.createCheckout({
            plan,
            billing_period: period,
            currency,
          });

          // Redirect to Peach Payments checkout
          window.location.href = response.checkout_url;
        } else {
          setError('Invalid checkout parameters');
          setLoading(false);
        }
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to initialize checkout');
        setLoading(false);
      }
    };

    initCheckout();
  }, [checkoutId, plan, period, currency, navigate]);

  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Paper sx={{ p: 4, textAlign: 'center' }}>
        {loading ? (
          <Box>
            <CircularProgress size={60} />
            <Typography variant="h6" sx={{ mt: 3 }}>
              {checkoutId ? 'Verifying payment...' : 'Redirecting to payment...'}
            </Typography>
          </Box>
        ) : error ? (
          <Alert severity="error">
            {error}
            <Box sx={{ mt: 2 }}>
              <Button variant="outlined" onClick={() => navigate('/pricing')}>
                Back to Pricing
              </Button>
            </Box>
          </Alert>
        ) : null}
      </Paper>
    </Container>
  );
};
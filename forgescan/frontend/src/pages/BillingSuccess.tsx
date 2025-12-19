// frontend/src/pages/BillingSuccess.tsx
import React from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Button,
} from '@mui/material';
import { CheckCircle } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

export const BillingSuccessPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Paper sx={{ p: 6, textAlign: 'center' }}>
        <CheckCircle sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Payment Successful!
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Your subscription has been activated. Thank you for choosing ForgeScan!
        </Typography>
        <Box sx={{ mt: 4, display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="contained"
            size="large"
            onClick={() => navigate('/dashboard')}
          >
            Go to Dashboard
          </Button>
          <Button
            variant="outlined"
            size="large"
            onClick={() => navigate('/billing')}
          >
            View Billing
          </Button>
        </Box>
      </Paper>
    </Container>
  );
};


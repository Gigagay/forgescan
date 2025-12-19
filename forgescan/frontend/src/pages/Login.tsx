import React from 'react';
import { Box, Container, Typography } from '@mui/material';
import { LoginForm } from '@/components/auth/LoginForm';

export const LoginPage: React.FC = () => {
  return (
    <Container maxWidth="sm">
      <Box sx={{ mt: 8 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Sign In
        </Typography>
        <LoginForm />
      </Box>
    </Container>
  );
};

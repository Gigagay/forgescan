// frontend/src/components/common/Loading.tsx
import React from 'react';
import { Box, CircularProgress, Typography } from '@mui/material';

export const Loading: React.FC = () => (
  <Box
    sx={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      gap: 2,
    }}
  >
    <CircularProgress size={60} />
    <Typography variant="h6" color="text.secondary">
      Loading...
    </Typography>
  </Box>
);
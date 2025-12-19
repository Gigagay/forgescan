// frontend/src/pages/Pricing.tsx
import React, { useState } from 'react';
import {
  Box,
  Container,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ToggleButtonGroup,
  ToggleButton,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import { Check } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

export const PricingPage: React.FC = () => {
  const navigate = useNavigate();
  const [billingPeriod, setBillingPeriod] = useState<'monthly' | 'yearly'>('monthly');
  const [currency, setCurrency] = useState('USD');

  const currencySymbols: Record<string, string> = {
    USD: '$',
    ZAR: 'R',
    KES: 'KSh',
  };

  const pricing = {
    developer: {
      monthly: { USD: 9, ZAR: 150, KES: 1200 },
      yearly: { USD: 90, ZAR: 1500, KES: 12000 },
    },
    startup: {
      monthly: { USD: 49, ZAR: 800, KES: 6500 },
      yearly: { USD: 490, ZAR: 8000, KES: 65000 },
    },
    professional: {
      monthly: { USD: 199, ZAR: 3200, KES: 26000 },
      yearly: { USD: 1990, ZAR: 32000, KES: 260000 },
    },
  };

  const plans = [
    {
      id: 'free',
      name: 'Free',
      description: 'Perfect for trying out ForgeScan',
      features: [
        '5 scans per month',
        '1 user',
        'Basic web scanning',
        '7-day retention',
        'Community support',
      ],
      cta: 'Start Free',
      highlighted: false,
      price: 0,
    },
    {
      id: 'developer',
      name: 'Developer',
      description: 'For indie developers and solo practitioners',
      features: [
        '50 scans per month',
        '1 user (personal use)',
        'Web + API scanning',
        '30-day retention',
        'Email support',
        'CI/CD integration',
        'API access',
        'PDF reports',
      ],
      cta: 'Start Building',
      highlighted: true,
      badge: '🔥 Most Popular',
      price: pricing.developer[billingPeriod][currency as keyof typeof pricing.developer.monthly],
    },
    {
      id: 'startup',
      name: 'Startup',
      description: 'For small teams and startups',
      features: [
        '200 scans per month',
        '5 users',
        'All scanners',
        '90-day retention',
        'Priority support',
        'Slack integration',
        'Scheduled scans',
        'Team collaboration',
      ],
      cta: 'Start Team Trial',
      highlighted: false,
      price: pricing.startup[billingPeriod][currency as keyof typeof pricing.startup.monthly],
    },
    {
      id: 'professional',
      name: 'Professional',
      description: 'For growing businesses',
      features: [
        '1,000 scans per month',
        '25 users',
        'All features',
        '180-day retention',
        'Dedicated support',
        'Custom branding',
        'SSO integration',
        'Compliance reports',
      ],
      cta: 'Start Pro Trial',
      highlighted: false,
      price: pricing.professional[billingPeriod][currency as keyof typeof pricing.professional.monthly],
    },
  ];

  const handleSelectPlan = (planId: string) => {
    if (planId === 'free') {
      navigate('/signup');
    } else {
      navigate(`/billing/checkout?plan=${planId}&period=${billingPeriod}&currency=${currency}`);
    }
  };

  const savings = billingPeriod === 'yearly' ? 17 : 0;

  return (
    <Container maxWidth="lg" sx={{ py: 8 }}>
      <Typography variant="h3" align="center" gutterBottom fontWeight="bold">
        Simple, Transparent Pricing
      </Typography>
      <Typography variant="h6" align="center" color="text.secondary" paragraph>
        Start free, upgrade as you grow
      </Typography>

      {/* Billing Period Toggle */}
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 3, mb: 4, mt: 4 }}>
        <ToggleButtonGroup
          value={billingPeriod}
          exclusive
          onChange={(_, value) => value && setBillingPeriod(value)}
          sx={{ bgcolor: 'background.paper' }}
        >
          <ToggleButton value="monthly">Monthly</ToggleButton>
          <ToggleButton value="yearly">
            Yearly
            {savings > 0 && (
              <Chip
                label={`Save ${savings}%`}
                color="success"
                size="small"
                sx={{ ml: 1 }}
              />
            )}
          </ToggleButton>
        </ToggleButtonGroup>

        {/* Currency Selector */}
        <FormControl sx={{ minWidth: 120 }}>
          <InputLabel>Currency</InputLabel>
          <Select
            value={currency}
            label="Currency"
            onChange={(e) => setCurrency(e.target.value)}
          >
            <MenuItem value="USD">USD ($)</MenuItem>
            <MenuItem value="ZAR">ZAR (R)</MenuItem>
            <MenuItem value="KES">KES (KSh)</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {/* Pricing Cards */}
      <Grid container spacing={3}>
        {plans.map((plan) => (
          <Grid item xs={12} md={3} key={plan.id}>
            <Card
              sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                position: 'relative',
                border: plan.highlighted ? '2px solid' : '1px solid',
                borderColor: plan.highlighted ? 'primary.main' : 'divider',
                transform: plan.highlighted ? 'scale(1.05)' : 'none',
              }}
            >
              {plan.badge && (
                <Chip
                  label={plan.badge}
                  color="primary"
                  size="small"
                  sx={{
                    position: 'absolute',
                    top: -12,
                    left: '50%',
                    transform: 'translateX(-50%)',
                  }}
                />
              )}
              <CardContent sx={{ flexGrow: 1, pt: plan.badge ? 4 : 3 }}>
                <Typography variant="h5" gutterBottom fontWeight="bold">
                  {plan.name}
                </Typography>
                <Typography color="text.secondary" paragraph sx={{ minHeight: 48 }}>
                  {plan.description}
                </Typography>
                <Box sx={{ mb: 3 }}>
                  {plan.id === 'free' ? (
                    <Typography variant="h3" fontWeight="bold">
                      Free
                    </Typography>
                  ) : (
                    <>
                      <Typography variant="h3" component="span" fontWeight="bold">
                        {currencySymbols[currency]}{plan.price}
                      </Typography>
                      <Typography variant="body1" component="span" color="text.secondary">
                        {' '}/ {billingPeriod === 'monthly' ? 'month' : 'year'}
                      </Typography>
                    </>
                  )}
                </Box>
                <List dense>
                  {plan.features.map((feature, idx) => (
                    <ListItem key={idx} disableGutters>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <Check color="primary" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={feature}
                        primaryTypographyProps={{ variant: 'body2' }}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
              <Box sx={{ p: 2 }}>
                <Button
                  fullWidth
                  variant={plan.highlighted ? 'contained' : 'outlined'}
                  size="large"
                  onClick={() => handleSelectPlan(plan.id)}
                >
                  {plan.cta}
                </Button>
              </Box>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Payment Methods */}
      <Box sx={{ mt: 6, textAlign: 'center' }}>
        <Typography variant="h6" gutterBottom>
          Secure Payments Powered by Peach Payments
        </Typography>
        <Typography variant="body2" color="text.secondary">
          We accept Credit/Debit Cards, EFT, Mobile Money, and more
        </Typography>
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 2 }}>
          {/* Add payment method logos */}
          <Chip label="💳 Credit Card" />
          <Chip label="🏦 EFT" />
          <Chip label="📱 Mobile Money" />
        </Box>
      </Box>
    </Container>
  );
};


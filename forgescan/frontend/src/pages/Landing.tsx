// frontend/src/pages/Landing.tsx
import React from 'react';
import {
  Box,
  Button,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Security,
  Speed,
  TrendingUp,
  Check,
  Code,
  Cloud,
  ShieldOutlined,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: <Security sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Web Security Scanning',
      description: 'Detect OWASP Top 10 vulnerabilities automatically',
    },
    {
      icon: <Code sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'API Security Testing',
      description: 'Test REST APIs for authentication and authorization flaws',
    },
    {
      icon: <Speed sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Lightning Fast',
      description: '3-5x faster than traditional scanners with parallel execution',
    },
    {
      icon: <TrendingUp sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Risk Intelligence',
      description: 'Smart prioritization using CVSS + EPSS scoring',
    },
    {
      icon: <Cloud sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Cloud Native',
      description: 'Built for modern DevOps workflows and CI/CD pipelines',
    },
    {
      icon: <ShieldOutlined sx={{ fontSize: 48, color: 'primary.main' }} />,
      title: 'Compliance Ready',
      description: 'OWASP, PCI-DSS, HIPAA compliance mapping',
    },
  ];

  const plans = [
    {
      name: 'Free',
      price: '$0',
      period: 'forever',
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
    },
    {
      name: 'Developer',
      price: '$9',
      period: 'per month',
      yearlyPrice: '$90/year (save 17%)',
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
    },
    {
      name: 'Startup',
      price: '$49',
      period: 'per month',
      yearlyPrice: '$490/year (save 17%)',
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
    },
    {
      name: 'Professional',
      price: '$199',
      period: 'per month',
      yearlyPrice: '$1,990/year (save 17%)',
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
    },
  ];

  return (
    <Box>
      {/* Hero Section */}
      <Box
        sx={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          color: 'white',
          pt: 12,
          pb: 16,
        }}
      >
        <Container maxWidth="lg">
          <Grid container spacing={4} alignItems="center">
            <Grid item xs={12} md={6}>
              <Typography variant="h2" component="h1" gutterBottom fontWeight="bold">
                Security Scanning for Modern Teams
              </Typography>
              <Typography variant="h5" paragraph sx={{ opacity: 0.9 }}>
                Find vulnerabilities before attackers do. Automated security testing
                for web applications and APIs.
              </Typography>
              <Box sx={{ mt: 4 }}>
                <Button
                  variant="contained"
                  size="large"
                  sx={{
                    mr: 2,
                    bgcolor: 'white',
                    color: 'primary.main',
                    '&:hover': { bgcolor: 'grey.100' },
                  }}
                  onClick={() => navigate('/signup')}
                >
                  Start Free Trial
                </Button>
                <Button
                  variant="outlined"
                  size="large"
                  sx={{
                    borderColor: 'white',
                    color: 'white',
                    '&:hover': { borderColor: 'white', bgcolor: 'rgba(255,255,255,0.1)' },
                  }}
                  onClick={() => navigate('/login')}
                >
                  Sign In
                </Button>
              </Box>
              <Typography variant="body2" sx={{ mt: 2, opacity: 0.8 }}>
                No credit card required • 5 free scans • Setup in 2 minutes
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box
                sx={{
                  bgcolor: 'rgba(255,255,255,0.1)',
                  backdropFilter: 'blur(10px)',
                  borderRadius: 2,
                  p: 3,
                }}
              >
                <Typography variant="h6" gutterBottom>
                  ✅ Trusted by 500+ developers
                </Typography>
                <Typography variant="body1" paragraph>
                  "Finally, security scanning that doesn't require a PhD. ForgeScan found
                  3 critical issues in my app within minutes."
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.8 }}>
                  — Sarah Chen, Indie Hacker
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* Features Section */}
      <Container maxWidth="lg" sx={{ py: 12 }}>
        <Typography variant="h3" align="center" gutterBottom fontWeight="bold">
          Everything You Need to Secure Your Apps
        </Typography>
        <Typography
          variant="h6"
          align="center"
          color="text.secondary"
          paragraph
          sx={{ mb: 6 }}
        >
          Powerful security testing tools without the enterprise complexity
        </Typography>

        <Grid container spacing={4}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={4} key={index}>
              <Card sx={{ height: '100%', textAlign: 'center', p: 2 }}>
                <CardContent>
                  <Box sx={{ mb: 2 }}>{feature.icon}</Box>
                  <Typography variant="h5" gutterBottom>
                    {feature.title}
                  </Typography>
                  <Typography color="text.secondary">{feature.description}</Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* Pricing Section */}
      <Box sx={{ bgcolor: 'grey.50', py: 12 }}>
        <Container maxWidth="lg">
          <Typography variant="h3" align="center" gutterBottom fontWeight="bold">
            Simple, Transparent Pricing
          </Typography>
          <Typography
            variant="h6"
            align="center"
            color="text.secondary"
            paragraph
            sx={{ mb: 6 }}
          >
            Start free, upgrade as you grow
          </Typography>

          <Grid container spacing={4}>
            {plans.map((plan, index) => (
              <Grid item xs={12} md={3} key={index}>
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
                    <Typography color="text.secondary" paragraph>
                      {plan.description}
                    </Typography>
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="h3" component="span" fontWeight="bold">
                        {plan.price}
                      </Typography>
                      <Typography variant="body1" component="span" color="text.secondary">
                        {' '}
                        / {plan.period}
                      </Typography>
                      {plan.yearlyPrice && (
                        <Typography variant="body2" color="primary.main" sx={{ mt: 1 }}>
                          {plan.yearlyPrice}
                        </Typography>
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
                      onClick={() => navigate('/signup')}
                    >
                      {plan.cta}
                    </Button>
                  </Box>
                </Card>
              </Grid>
            ))}
          </Grid>

          <Box sx={{ mt: 6, textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              Need more? Enterprise plans available
            </Typography>
            <Button variant="text" size="large">
              Contact Sales
            </Button>
          </Box>
        </Container>
      </Box>

      {/* CTA Section */}
      <Container maxWidth="md" sx={{ py: 12, textAlign: 'center' }}>
        <Typography variant="h3" gutterBottom fontWeight="bold">
          Start Securing Your Apps Today
        </Typography>
        <Typography variant="h6" color="text.secondary" paragraph>
          Join hundreds of developers who trust ForgeScan
        </Typography>
        <Button
          variant="contained"
          size="large"
          sx={{ mt: 2 }}
          onClick={() => navigate('/signup')}
        >
          Get Started Free
        </Button>
      </Container>
    </Box>
  );
};


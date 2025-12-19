# Deployment Guide

## Prerequisites
- Fly.io account
- Peach Payments credentials
- Domain name (optional)

## Deploy Backend

```bash
flyctl launch --name forgescan-api
flyctl postgres create --name forgescan-db
flyctl postgres attach forgescan-db
flyctl secrets set SECRET_KEY=xxx JWT_SECRET_KEY=xxx
flyctl deploy
```

## Deploy Frontend

```bash
cd frontend
vercel --prod
```

See README.md for detailed instructions.

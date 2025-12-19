#!/bin/bash
set -e

echo "Setting up ForgeScan..."

# Generate secret keys
echo "Generating secret keys..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$JWT_SECRET_KEY/" .env
    echo "✓ Created .env file with generated secrets"
fi

echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your Peach Payments credentials"
echo "  2. Run: docker-compose up -d"
echo "  3. Run: docker-compose exec backend alembic upgrade head"
echo "  4. Visit: http://localhost:3000"

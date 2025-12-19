help:
	@echo "ForgeScan Development Commands"
	@echo "=============================="
	@echo "make dev       - Start development environment"
	@echo "make build     - Build Docker images"
	@echo "make test      - Run tests"
	@echo "make migrate   - Run database migrations"
	@echo "make seed      - Seed database"
	@echo "make clean     - Clean up"

dev:
	docker-compose up -d

build:
	docker-compose build

test:
	docker-compose exec backend pytest -v

migrate:
	docker-compose exec backend alembic upgrade head

seed:
	docker-compose exec backend python scripts/seed-data.py

clean:
	docker-compose down -v

logs:
	docker-compose logs -f

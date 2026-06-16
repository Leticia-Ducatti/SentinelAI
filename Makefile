.PHONY: install test serve benchmark docker-build docker-run

install:
	pip install -e ".[dev]"

test:
	pytest -q

serve:
	uvicorn sentinel.service.app:app --reload

benchmark:
	python -m sentinel.benchmark

docker-build:
	docker build -t sentinelai .

docker-run:
	docker run --rm -p 8000:8000 sentinelai

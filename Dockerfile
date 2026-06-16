FROM python:3.11-slim

WORKDIR /app

# Install the package (runtime deps come from setup.py install_requires).
COPY setup.py ./
COPY src ./src
RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd --create-home sentinel
USER sentinel

EXPOSE 8000
CMD ["uvicorn", "sentinel.service.app:app", "--host", "0.0.0.0", "--port", "8000"]

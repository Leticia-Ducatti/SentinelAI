from setuptools import find_packages, setup

setup(
    name="sentinel",
    version="0.1.0",
    description="SentinelAI: risk monitoring for LLM applications",
    author="Leticia Ducatti",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.11",
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "scipy>=1.11.0",
        "joblib>=1.3.0",
        "fastapi>=0.110.0",
        "uvicorn>=0.29.0",
    ],
    extras_require={
        "semantic": ["sentence-transformers>=2.2.0"],
        # Optional LLM backend. Ollama (the free, local path) needs no Python
        # package; this extra is only for the Anthropic API path.
        "llm": ["anthropic>=0.40.0"],
        "otel": [
            "opentelemetry-sdk>=1.20.0",
            "opentelemetry-exporter-otlp-proto-http>=1.20.0",
        ],
        "dev": ["pytest>=7.4.0", "pytest-cov>=4.1.0", "httpx>=0.27.0"],
    },
    entry_points={
        "console_scripts": [
            "sentinel-serve=sentinel.service.app:main",
            "sentinel-benchmark=sentinel.benchmark:main",
            "sentinel-train=sentinel.train:main",
        ],
    },
)

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY helmgate/ helmgate/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["helmgate"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
COPY pyproject.toml .
COPY README.md .
COPY sec_assess ./sec_assess
COPY examples ./examples

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e .

RUN mkdir -p reports

ENTRYPOINT ["sec-assess"]
FROM python:3.13-slim

WORKDIR /app

COPY setup.py setup.cfg ROPgadget.py ./
COPY ropgadget/ ./ropgadget/
COPY scripts/ ./scripts/

RUN pip install --no-cache-dir capstone>=5.0.1 && \
    pip install --no-cache-dir .

WORKDIR /work

ENTRYPOINT ["ROPgadget"]

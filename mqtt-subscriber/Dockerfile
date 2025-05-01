FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY subscriber.py .

RUN pip3 install --no-cache-dir paho-mqtt tabulate

CMD ["python3", "subscriber.py"]


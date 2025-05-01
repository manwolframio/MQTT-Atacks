FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY publisher.py .

RUN pip3 install paho-mqtt
RUN pip install ntplib paho-mqtt

CMD ["python3", "publisher.py"]


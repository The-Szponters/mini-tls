FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y tcpdump && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

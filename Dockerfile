FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY LICENSE ./
COPY LICENSES ./LICENSES

RUN useradd --system --uid 10001 --no-create-home --home-dir /data app \
    && mkdir /data && chown app /data
USER 10001
VOLUME /data

ENTRYPOINT ["python", "-m", "firmware_index"]
EXPOSE 8080
CMD ["serve"]

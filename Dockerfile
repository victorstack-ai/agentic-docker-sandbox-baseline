FROM python:3.12-slim

RUN useradd --create-home --uid 10001 appuser
WORKDIR /app

COPY src /app/src
USER appuser

CMD ["python", "-c", "print('agent sandbox baseline container image')"]

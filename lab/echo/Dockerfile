FROM python:3-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
COPY echo/server.py /app/server.py
EXPOSE 80 443 8443 9443
HEALTHCHECK NONE
CMD ["python", "/app/server.py", "--name", "echo", "--log", "/state/logs/echo.log", "--http", "80", "--https", "443:echo.lab.test"]

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY check_isolation.py .
RUN useradd -m agentuser
USER agentuser
CMD ["python", "check_isolation.py"]
FROM python:3.12-slim
WORKDIR /app
COPY check_isolation.py .
RUN useradd -m agentuser
USER agentuser
CMD ["python", "check_isolation.py"]
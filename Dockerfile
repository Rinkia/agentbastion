# agentbastion HTTP gateway (hosted tier).
# Build:  docker build -t agentbastion-gateway .
# Run:    docker run -p 8080:8080 -e AGENTBASTION_API_KEY=<secret> \
#                 -e ANTHROPIC_API_KEY=<optional, enables judge> agentbastion-gateway
FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[gateway,judge]"

EXPOSE 8080
ENV HOST=0.0.0.0 PORT=8080

# Fail-closed: without AGENTBASTION_API_KEY the gateway refuses requests (503).
CMD ["agentbastion-gateway"]

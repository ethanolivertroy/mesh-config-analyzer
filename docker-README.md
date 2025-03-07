# Deploying the Service Mesh Configuration Security Analyzer with Docker

This guide explains how to deploy the Service Mesh Configuration Security Analyzer tool using Docker, which eliminates the need to install Node.js or any other dependencies on your local machine. The analyzer supports Istio, Consul, and Linkerd service mesh configurations.

## Prerequisites

- Docker installed on your system
  - [Docker Desktop for Windows/Mac](https://www.docker.com/products/docker-desktop)
  - [Docker Engine for Linux](https://docs.docker.com/engine/install/)

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://gitlab.com/yourusername/mesh-config-analyzer.git
   cd mesh-config-analyzer
   ```

2. Build the Docker image:
   ```bash
   docker build -t mesh-config-analyzer .
   ```

3. Run the container:
   ```bash
   docker run -p 3000:3000 mesh-config-analyzer
   ```

4. Access the application in your browser:
   ```
   http://localhost:3000
   ```

## Using a Pre-built Image

If a pre-built image is available in your organization's container registry:

```bash
# Pull the image from GitLab registry
docker pull registry.gitlab.com/yourusername/mesh-config-analyzer:latest

# Run the container
docker run -p 3000:3000 registry.gitlab.com/yourusername/mesh-config-analyzer:latest
```

## Running as a Service

For running the analyzer as a long-lived service, consider using Docker Compose:

1. Create a `docker-compose.yml` file:
   ```yaml
   version: '3'
   services:
     analyzer:
       image: registry.gitlab.com/yourusername/mesh-config-analyzer:latest
       ports:
         - "3000:3000"
       restart: unless-stopped
       volumes:
         - ./data:/usr/src/app/uploads
   ```

2. Start the service:
   ```bash
   docker-compose up -d
   ```

3. Stop the service:
   ```bash
   docker-compose down
   ```

## Troubleshooting

- If you can't access the application, ensure port 3000 isn't blocked by a firewall
- Check container logs with: `docker logs [container-id]`
- If the container exits immediately, check for errors in the logs

## Using the Analyzer

1. Once the application is running, open your web browser and go to http://localhost:3000
2. Upload your service mesh configuration file (YAML or JSON) using the web interface
3. The analyzer will automatically detect whether it's an Istio, Consul, or Linkerd configuration
4. Review the security findings categorized by severity (Critical, High, Medium, Low)
5. Use the filter options to focus on specific severity levels
6. Follow the detailed recommendations to improve your mesh security posture
7. Use the theme switcher in the header to select your preferred UI theme
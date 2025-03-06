# Istio MeshConfig Security Analyzer

A web application for analyzing Istio MeshConfig resources against security best practices.

## Features

- Upload and analyze Istio MeshConfig YAML files
- Detailed security checks for over 10 critical security areas
- Severity-based findings with recommendations
- User-friendly web interface with filtering options
- Displays specific locations in the configuration that need attention

## Security Checks

The analyzer evaluates your MeshConfig against the following security best practices:

- **mTLS Configuration**: Ensures mesh-wide mTLS is enabled and set to STRICT mode
- **Certificate Authority**: Validates CA settings and certificate validity durations
- **Peer Authentication**: Verifies proper peer authentication settings
- **Proxy Configuration**: Checks for proper proxy settings, especially privileged mode
- **Secret Discovery Service**: Confirms SDS is enabled for secure certificate distribution
- **Trust Domain**: Validates trust domain settings
- **Authorization Policies**: Checks for proper default deny policy
- **Telemetry & Logging**: Ensures proper telemetry and access logging for security monitoring
- **RBAC**: Verifies RBAC enforcement is enabled
- **Outbound Traffic Policy**: Checks outbound traffic policy mode to prevent data exfiltration

## Installation

1. Clone the repository.

2. Install dependencies:
   ```
   npm install
   ```

3. Start the server:
   ```
   npm start
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Development

For development with auto-reload:

```
npm run dev
```

## Running Tests

```
npm test
```

## Usage

1. Upload your Istio MeshConfig YAML file using the web interface
2. Review the findings categorized by severity (Critical, High, Medium, Low)
3. Use the filter options to focus on specific severity levels
4. Review detailed recommendations for each finding

## Sample MeshConfig

A sample MeshConfig with various security issues is included in the `samples` directory to help you test the analyzer.

## Project Structure

```
├── app.js               # Express server and analyzer implementation
├── public/              # Static web assets
│   └── index.html       # Web interface
├── tests/               # Test files
│   └── analyzer.test.js # Unit tests for the analyzer
├── samples/             # Sample MeshConfig files
└── uploads/             # Temporary directory for file uploads
```

## Key Security Guidelines

When configuring your Istio mesh, follow these key security guidelines:

1. **Always use STRICT mTLS mode** for service-to-service communication
2. **Enable RBAC** for authorization control
3. **Set outbound traffic policy to REGISTRY_ONLY** to prevent unauthorized external communication
4. **Avoid running proxies in privileged mode** unless absolutely necessary
5. **Enable telemetry and access logging** for security monitoring
6. **Use proper certificate management** with SDS enabled and appropriate validity periods
7. **Hold application starts until proxy is ready** to prevent traffic leaks
8. **Use custom trust domains** to isolate identities
9. **Apply a default deny authorization policy** and explicitly allow required traffic
10. **Use external certificate authorities** for production environments

## License

[MIT](LICENSE)

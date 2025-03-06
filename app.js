// app.js - Express server for Istio MeshConfig Security Analyzer

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const app = express();
const port = 3000;
const upload = multer({ dest: 'uploads/' });

// Serve static files
app.use(express.static('public'));
app.use(express.json());

class IstioSecurityAnalyzer {
  constructor() {
    this.findings = [];
  }

  reset() {
    this.findings = [];
  }

  addFinding(severity, category, message, recommendation, location = null) {
    this.findings.push({
      severity,
      category,
      message,
      recommendation,
      location
    });
  }

  analyze(config) {
    this.reset();
    
    // Analyze overall structure
    if (!config) {
      this.addFinding('Critical', 'File Format', 'Invalid or empty configuration file', 'Provide a valid Istio MeshConfig');
      return this.findings;
    }
    
    // Check if it's a valid Istio resource
    if (!config.kind || !config.apiVersion) {
      this.addFinding('Critical', 'Resource Type', 'File is not a valid Kubernetes resource', 'Ensure the file has apiVersion and kind fields');
      return this.findings;
    }
    
    // Check MeshConfig type
    if (config.kind !== 'MeshConfig') {
      this.addFinding('Critical', 'Resource Type', `Expected MeshConfig but found ${config.kind}`, 'Use a valid Istio MeshConfig resource');
      return this.findings;
    }

    // Run security checks
    this.checkMTLS(config);
    this.checkRootCertificates(config);
    this.checkPeerAuthentication(config);
    this.checkProxyConfig(config);
    this.checkSDS(config);
    this.checkTrustDomain(config);
    this.checkAuthorizationPolicies(config);
    this.checkTelemetry(config);
    this.checkRBAC(config);
    this.checkOutboundTrafficPolicy(config);
    
    return this.findings;
  }

  checkMTLS(config) {
    // Check if mTLS is enabled
    if (!config.meshMTLS || !config.meshMTLS.enabled) {
      this.addFinding(
        'High', 
        'mTLS', 
        'Mesh-wide mTLS is not enabled', 
        'Enable mesh-wide mTLS for service-to-service communication security',
        'meshMTLS.enabled'
      );
    }
    
    // Check mTLS mode (STRICT is most secure)
    if (config.meshMTLS && config.meshMTLS.mode !== 'STRICT') {
      this.addFinding(
        'Medium', 
        'mTLS', 
        `mTLS mode is set to ${config.meshMTLS.mode || 'PERMISSIVE'} instead of STRICT`, 
        'Use STRICT mode for mTLS to ensure all traffic is encrypted',
        'meshMTLS.mode'
      );
    }
  }

  checkRootCertificates(config) {
    const ca = config.ca || {};
    
    if (!ca.provider || ca.provider === 'istiod') {
      this.addFinding(
        'Medium', 
        'Certificate Authority', 
        'Using default istiod CA instead of a custom CA', 
        'Consider using a production-grade external CA for production environments',
        'ca.provider'
      );
    }
    
    if (!ca.certValidityDuration) {
      this.addFinding(
        'Low', 
        'Certificate Validity', 
        'Certificate validity duration not specified', 
        'Set appropriate cert validity periods based on your security policies',
        'ca.certValidityDuration'
      );
    } else if (parseInt(ca.certValidityDuration) > 8760) { // More than a year
      this.addFinding(
        'Medium', 
        'Certificate Validity', 
        'Long certificate validity period detected', 
        'Consider shorter certificate validity periods (e.g., 90 days) for better security',
        'ca.certValidityDuration'
      );
    }
  }

  checkPeerAuthentication(config) {
    if (!config.peerAuthentication || !config.peerAuthentication.mode) {
      this.addFinding(
        'High', 
        'Authentication', 
        'No default peer authentication policy defined', 
        'Define a default peer authentication policy with strict mTLS',
        'peerAuthentication'
      );
    } else if (config.peerAuthentication.mode !== 'STRICT') {
      this.addFinding(
        'Medium', 
        'Authentication', 
        `Peer authentication mode is set to ${config.peerAuthentication.mode} instead of STRICT`, 
        'Use STRICT mode for peer authentication to ensure all traffic is authenticated',
        'peerAuthentication.mode'
      );
    }
  }

  checkProxyConfig(config) {
    const proxyConfig = config.defaultConfig || {};
    
    // Check privileged mode
    if (proxyConfig.privileged === true) {
      this.addFinding(
        'High', 
        'Proxy Configuration', 
        'Proxies are running in privileged mode', 
        'Avoid running proxies in privileged mode unless absolutely necessary',
        'defaultConfig.privileged'
      );
    }
    
    // Check proxy image version (placeholder - would need to be updated with version logic)
    if (proxyConfig.image && proxyConfig.image.includes(':')) {
      const version = proxyConfig.image.split(':')[1];
      if (version === 'latest' || version === 'master') {
        this.addFinding(
          'Medium', 
          'Proxy Configuration', 
          `Using non-specific proxy image version: ${version}`, 
          'Use specific, pinned versions of proxy images',
          'defaultConfig.image'
        );
      }
    }
    
    // Check if holdApplicationUntilProxyStarts is set
    if (proxyConfig.holdApplicationUntilProxyStarts !== true) {
      this.addFinding(
        'Medium', 
        'Proxy Configuration', 
        'Applications may start before proxy initialization is complete', 
        'Set holdApplicationUntilProxyStarts to true to prevent traffic leaks',
        'defaultConfig.holdApplicationUntilProxyStarts'
      );
    }
  }

  checkSDS(config) {
    // Check if SDS is being used
    const proxyConfig = config.defaultConfig || {};
    
    if (!proxyConfig.sds || !proxyConfig.sds.enabled) {
      this.addFinding(
        'Medium', 
        'Secret Discovery Service', 
        'SDS is not enabled for certificate management', 
        'Enable SDS for secure certificate distribution and rotation',
        'defaultConfig.sds.enabled'
      );
    }
  }

  checkTrustDomain(config) {
    if (!config.trustDomain) {
      this.addFinding(
        'Medium', 
        'Trust Domain', 
        'Trust domain not explicitly configured', 
        'Set a specific trust domain for your mesh to isolate identities',
        'trustDomain'
      );
    } else if (config.trustDomain === 'cluster.local') {
      this.addFinding(
        'Low', 
        'Trust Domain', 
        'Using default trust domain (cluster.local)', 
        'Consider setting a custom trust domain specific to your organization',
        'trustDomain'
      );
    }
  }

  checkAuthorizationPolicies(config) {
    // Check for default deny policy (this is a higher-level concept, might not be in MeshConfig directly)
    if (!config.defaultAuthorizationPolicy || config.defaultAuthorizationPolicy.action !== 'DENY') {
      this.addFinding(
        'High', 
        'Authorization', 
        'No default deny policy is configured at mesh level', 
        'Configure a default DENY policy and explicitly allow required traffic',
        'defaultAuthorizationPolicy'
      );
    }
  }

  checkTelemetry(config) {
    const telemetry = config.telemetry || {};
    
    if (!telemetry.enabled) {
      this.addFinding(
        'Medium', 
        'Telemetry', 
        'Telemetry collection is disabled', 
        'Enable telemetry for security monitoring and incident detection',
        'telemetry.enabled'
      );
    }
    
    if (!telemetry.accessLogging || !telemetry.accessLogging.enabled) {
      this.addFinding(
        'Medium', 
        'Access Logging', 
        'Access logging is not enabled', 
        'Enable access logging for security auditing and forensics',
        'telemetry.accessLogging.enabled'
      );
    }
  }

  checkRBAC(config) {
    if (!config.rbac || config.rbac.mode !== 'ON') {
      this.addFinding(
        'Critical', 
        'RBAC', 
        'RBAC enforcement is not enabled', 
        'Enable RBAC to control service-to-service authorization',
        'rbac.mode'
      );
    }
  }

  checkOutboundTrafficPolicy(config) {
    const outboundTrafficPolicy = config.outboundTrafficPolicy || {};
    
    if (outboundTrafficPolicy.mode !== 'REGISTRY_ONLY') {
      this.addFinding(
        'High', 
        'Traffic Policy', 
        'Outbound traffic to external services is allowed by default', 
        'Set outboundTrafficPolicy.mode to REGISTRY_ONLY to restrict external access',
        'outboundTrafficPolicy.mode'
      );
    }
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/analyze', upload.single('meshconfig'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const filePath = req.file.path;
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    let config;
    try {
      config = yaml.load(fileContent);
    } catch (e) {
      return res.status(400).json({
        success: false,
        message: 'Invalid YAML file: ' + e.message
      });
    }

    const analyzer = new IstioSecurityAnalyzer();
    const findings = analyzer.analyze(config);
    
    // Clean up the uploaded file
    fs.unlinkSync(filePath);
    
    res.json({
      success: true,
      findings: findings,
      summary: {
        critical: findings.filter(f => f.severity === 'Critical').length,
        high: findings.filter(f => f.severity === 'High').length,
        medium: findings.filter(f => f.severity === 'Medium').length,
        low: findings.filter(f => f.severity === 'Low').length,
        total: findings.length
      }
    });
  } catch (error) {
    console.error('Error analyzing file:', error);
    res.status(500).json({
      success: false,
      message: 'Server error: ' + error.message
    });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Istio MeshConfig Security Analyzer running at http://localhost:${port}`);
});

module.exports = { IstioSecurityAnalyzer };

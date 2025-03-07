const { IstioSecurityAnalyzer, ConsulSecurityAnalyzer } = require('../app');
const fs = require('fs');
const yaml = require('js-yaml');
const path = require('path');

describe('IstioSecurityAnalyzer', () => {
  let analyzer;
  let sampleConfig;

  beforeEach(() => {
    analyzer = new IstioSecurityAnalyzer();
    const sampleFilePath = path.join(__dirname, '..', 'samples', 'sample-meshconfig.yaml');
    const fileContent = fs.readFileSync(sampleFilePath, 'utf8');
    sampleConfig = yaml.load(fileContent);
  });

  test('should analyze a valid MeshConfig', () => {
    const findings = analyzer.analyze(sampleConfig);
    expect(findings).toBeDefined();
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('should detect critical RBAC issues', () => {
    const findings = analyzer.analyze(sampleConfig);
    const rbacFinding = findings.find(f => f.category === 'RBAC');
    expect(rbacFinding).toBeDefined();
    expect(rbacFinding.severity).toBe('Critical');
    expect(rbacFinding.location).toBe('rbac.mode');
  });

  test('should detect mTLS findings', () => {
    const findings = analyzer.analyze(sampleConfig);
    const mtlsFindings = findings.filter(f => f.category === 'mTLS');
    
    // Verify we have mTLS findings
    expect(mtlsFindings.length).toBeGreaterThan(0);
    
    // For now, let's just check that we have mTLS findings with the right severity
    expect(mtlsFindings[0].severity).toBe('High');
    expect(mtlsFindings[0].location).toBe('meshMTLS.enabled');
  });

  test('should handle empty configuration', () => {
    const findings = analyzer.analyze(null);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('Critical');
    expect(findings[0].category).toBe('File Format');
  });

  test('should handle non-MeshConfig resources', () => {
    const invalidConfig = { ...sampleConfig, kind: 'Service' };
    const findings = analyzer.analyze(invalidConfig);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('Critical');
    expect(findings[0].category).toBe('Resource Type');
  });

  test('should reset findings between analyses', () => {
    analyzer.analyze(sampleConfig);
    expect(analyzer.findings.length).toBeGreaterThan(0);
    
    analyzer.reset();
    expect(analyzer.findings.length).toBe(0);
  });

  test('should add findings correctly', () => {
    analyzer.addFinding('High', 'Test', 'Test message', 'Test recommendation', 'test.location');
    expect(analyzer.findings.length).toBe(1);
    expect(analyzer.findings[0]).toEqual({
      severity: 'High',
      category: 'Test',
      message: 'Test message',
      recommendation: 'Test recommendation',
      location: 'test.location',
      nistControls: [],
      nistGuidance: null
    });
  });
});

describe('ConsulSecurityAnalyzer', () => {
  let analyzer;
  let sampleConfig;

  beforeEach(() => {
    analyzer = new ConsulSecurityAnalyzer();
    const sampleFilePath = path.join(__dirname, '..', 'samples', 'sample-consul-config.json');
    const fileContent = fs.readFileSync(sampleFilePath, 'utf8');
    sampleConfig = JSON.parse(fileContent);
  });

  test('should analyze a valid Consul config', () => {
    const findings = analyzer.analyze(sampleConfig);
    expect(findings).toBeDefined();
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('should detect ACL issues', () => {
    const findings = analyzer.analyze(sampleConfig);
    const aclFinding = findings.find(f => f.category === 'Access Control');
    expect(aclFinding).toBeDefined();
    expect(aclFinding.severity).toBe('Critical');
    expect(aclFinding.location).toBe('acl.enabled');
  });

  test('should detect TLS security issues', () => {
    const findings = analyzer.analyze(sampleConfig);
    const tlsFindings = findings.filter(f => f.category === 'TLS Security');
    expect(tlsFindings.length).toBeGreaterThan(0);
  });
  
  test('should detect FedRAMP compliance issues', () => {
    const findings = analyzer.analyze(sampleConfig);
    const fedRampFindings = findings.filter(f => f.category === 'FedRAMP Compliance');
    expect(fedRampFindings.length).toBeGreaterThan(0);
  });
  
  test('should detect gossip encryption issues', () => {
    const findings = analyzer.analyze(sampleConfig);
    const gossipFindings = findings.filter(f => f.category === 'Gossip Security');
    expect(gossipFindings.length).toBeGreaterThan(0);
  });

  test('should handle empty configuration', () => {
    const findings = analyzer.analyze(null);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('Critical');
    expect(findings[0].category).toBe('File Format');
  });

  test('should handle non-Consul configurations', () => {
    const invalidConfig = { ...sampleConfig, mesh_type: 'something-else' };
    const findings = analyzer.analyze(invalidConfig);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('Critical');
    expect(findings[0].category).toBe('Resource Type');
  });

  test('should reset findings between analyses', () => {
    analyzer.analyze(sampleConfig);
    expect(analyzer.findings.length).toBeGreaterThan(0);
    
    analyzer.reset();
    expect(analyzer.findings.length).toBe(0);
  });
});
// tests/analyzer.test.js
const { IstioSecurityAnalyzer } = require('../app');

describe('Istio Security Analyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new IstioSecurityAnalyzer();
  });

  test('should detect missing mTLS configuration', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      // No meshMTLS field
    };

    const findings = analyzer.analyze(config);
    
    expect(findings.some(f => 
      f.category === 'mTLS' && 
      f.severity === 'High' && 
      f.message.includes('not enabled')
    )).toBe(true);
  });

  test('should detect non-strict mTLS mode', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      meshMTLS: {
        enabled: true,
        mode: 'PERMISSIVE'  // Not STRICT
      }
    };

    const findings = analyzer.analyze(config);
    
    expect(findings.some(f => 
      f.category === 'mTLS' && 
      f.message.includes('PERMISSIVE instead of STRICT')
    )).toBe(true);
  });

  test('should detect privileged proxies', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      defaultConfig: {
        privileged: true  // Security concern
      }
    };

    const findings = analyzer.analyze(config);
    
    expect(findings.some(f => 
      f.category === 'Proxy Configuration' && 
      f.severity === 'High' && 
      f.message.includes('privileged mode')
    )).toBe(true);
  });

  test('should detect outbound traffic policy issues', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      outboundTrafficPolicy: {
        mode: 'ALLOW_ANY'  // Not REGISTRY_ONLY
      }
    };

    const findings = analyzer.analyze(config);
    
    expect(findings.some(f => 
      f.category === 'Traffic Policy' && 
      f.severity === 'High'
    )).toBe(true);
  });

  test('should detect RBAC not enabled', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      rbac: {
        mode: 'OFF'  // Not ON
      }
    };

    const findings = analyzer.analyze(config);
    
    expect(findings.some(f => 
      f.category === 'RBAC' && 
      f.severity === 'Critical' && 
      f.message.includes('not enabled')
    )).toBe(true);
  });

  test('should pass secure configuration', () => {
    const config = {
      kind: 'MeshConfig',
      apiVersion: 'networking.istio.io/v1alpha1',
      meshMTLS: {
        enabled: true,
        mode: 'STRICT'
      },
      defaultConfig: {
        privileged: false,
        holdApplicationUntilProxyStarts: true,
        sds: { enabled: true }
      },
      outboundTrafficPolicy: {
        mode: 'REGISTRY_ONLY'
      },
      rbac: {
        mode: 'ON'
      },
      telemetry: {
        enabled: true,
        accessLogging: { enabled: true }
      },
      peerAuthentication: {
        mode: 'STRICT'
      },
      trustDomain: 'example.com',
      defaultAuthorizationPolicy: {
        action: 'DENY'
      }
    };

    const findings = analyzer.analyze(config);
    
    // Should not have critical or high severity findings
    expect(findings.filter(f => 
      f.severity === 'Critical' || f.severity === 'High'
    ).length).toBe(0);
  });
});

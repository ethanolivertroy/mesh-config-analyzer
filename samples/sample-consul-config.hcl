# Main Consul Service Mesh Configuration
mesh_type = "consul"

connect {
  enabled = true
  
  proxy {
    allow_privileged = true
    connect_timeout = "5s"
    envoy_stats_bind_addr = "0.0.0.0:9102"
    local_connect_timeout_ms = 1000
  }
  
  ca_provider = "consul"
  
  ca_config {
    leaf_cert_ttl = "72h"
    root_cert_ttl = "87600h"
    rotate_cert_ttl = "24h"
    rotation_period = "720h"
  }
}

tls {
  defaults {
    verify_incoming = false
    verify_outgoing = true
  }
  
  internal_rpc {
    verify_server_hostname = false
  }
}

acl {
  enabled = false
  default_policy = "allow"
  
  tokens {
    agent = ""
    default = ""
  }
}

telemetry {
  disable_compat_1.9 = true
  disable_hostname = false
  prometheus_retention_time = "15s"
  enable_service_metrics = false
  filter_default = false
}

auto_encrypt {
  tls = false
  allow_tls = false
}

auto_config {
  enabled = false
  
  authorization {
    enabled = false
    
    static {
      allow_reuse = false
    }
  }
}
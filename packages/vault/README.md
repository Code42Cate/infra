# HashiCorp Vault Deployment

This package deploys HashiCorp Vault 1.14.8 on Nomad with Consul as the storage backend.

## Overview

Vault is deployed as a highly available cluster with the following features:
- **Version**: 1.14.8
- **Storage Backend**: Consul
- **High Availability**: 1 server node (TODO: increase to 3 for production)
- **Auto-Unseal**: GCP Cloud KMS integration for automatic unsealing
- **Service Discovery**: Registered with Consul
- **Authentication**: Pre-configured AppRoles for API and Orchestrator services
- **Secrets Engine**: KV v2 enabled at `secret/`
- **Ports**:
  - API: 8200
  - Cluster: 8201

## Directory Structure

```
packages/vault/
├── vault.hcl                 # Nomad job specification
├── main.tf                   # Terraform configuration
├── outputs.tf                # Terraform outputs
├── variables.tf              # Terraform variables
├── configs/
│   └── vault-config.hcl     # Vault server configuration template
├── scripts/
│   └── init-vault.sh        # Vault initialization with auto-unseal and AppRoles
└── README.md
```

## Prerequisites

1. **Consul** must be running and accessible
2. **Nomad** cluster must be operational
3. **GCP Secret Manager** for storing recovery keys (with auto-unseal) or unseal keys (manual)
4. **GCP Cloud KMS** for auto-unseal functionality
5. **Disk Image** must include Vault installation (already configured in `cluster-disk-image`)

## Deployment

```bash
cd packages/vault/scripts

# Initialize Vault with GCP KMS auto-unseal and configure AppRoles
./init-vault.sh \
  --project <gcp-project-id> \
  --prefix <environment-prefix> \
  --vault-addr http://vault.service.consul:8200
```

This script will:
- Initialize Vault with 5 recovery shares and 3 recovery threshold
- Store recovery keys in GCP Secret Manager (used for emergency procedures only)
- Store root token in GCP Secret Manager
- Configure GCP KMS auto-unseal (Vault automatically unseals on restart)
- Enable KV v2 secrets engine at `secret/`
- Create AppRoles for services:
  - **API Service** (`api-service`): Write and delete permissions
  - **Orchestrator Service** (`orchestrator-service`): Read-only permissions
- Save AppRole credentials to GCP Secret Manager

**Note**: The script is idempotent and can be safely re-run. It will skip creating AppRoles if they already exist.

### 3. AppRole Authentication

The initialization script automatically creates two AppRoles:

#### API Service AppRole
- **Role**: `api-service`
- **Permissions**: Full CRUD operations on secrets
- **Credentials**: Stored in `${prefix}vault-api-approle` secret
- **Policy**:
  ```hcl
  path "secret/data/*" {
    capabilities = ["create", "update", "delete"]
  }
  path "secret/metadata/*" {
    capabilities = ["create", "update", "delete", "read", "list"]
  }
  ```

#### Orchestrator Service AppRole
- **Role**: `orchestrator-service`
- **Permissions**: Read-only access to secrets
- **Credentials**: Stored in `${prefix}vault-orchestrator-approle` secret
- **Policy**:
  ```hcl
  path "secret/data/*" {
    capabilities = ["read"]
  }
  path "secret/metadata/*" {
    capabilities = ["read", "list"]
  }
  ```

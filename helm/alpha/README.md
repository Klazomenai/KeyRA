# alpha

KeyRA Alpha Landing Page with Ethereum Wallet Authentication

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity for pod assignment |
| auth.chainId | string | `""` | Chain ID for SIWE messages |
| auth.contractAddress | string | `""` | KeyRAAccessControl contract address |
| auth.domain | string | `""` | Domain for SIWE messages |
| auth.existingSecret | string | `""` | Name of existing secret containing SESSION_SECRET |
| auth.existingSecretKey | string | `"session-secret"` | Key in existing secret for SESSION_SECRET |
| auth.rpcUrl | string | `""` | Ethereum JSON-RPC endpoint |
| auth.sessionTtlSecs | string | `"3600"` | Session TTL in seconds |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"ghcr.io/klazomenai/keyra/alpha"` | Image repository |
| image.tag | string | `"latest"` | Image tag (defaults to chart appVersion) |
| livenessProbe | object | See values.yaml | Liveness probe configuration |
| namespace.create | bool | `true` | Create the namespace |
| namespace.name | string | `"alpha"` | Namespace name |
| nodeSelector | object | `{}` | Node selector for pod assignment |
| podSecurityContext | object | See values.yaml | Pod security context |
| readinessProbe | object | See values.yaml | Readiness probe configuration |
| replicaCount | int | `1` | Number of replicas |
| resources.limits.cpu | string | `"50m"` | CPU limit |
| resources.limits.memory | string | `"32Mi"` | Memory limit |
| resources.requests.cpu | string | `"10m"` | CPU request |
| resources.requests.memory | string | `"16Mi"` | Memory request |
| securityContext | object | See values.yaml | Container security context |
| service.port | int | `80` | Service port |
| service.type | string | `"ClusterIP"` | Service type |
| tolerations | list | `[]` | Tolerations for pod assignment |

## Installing

```bash
helm install alpha ./helm/alpha
```

With authentication enabled:

```bash
helm install alpha ./helm/alpha \
  --set auth.rpcUrl="http://autonity-rpc:8545" \
  --set auth.contractAddress="0x..." \
  --set auth.chainId="65111111" \
  --set auth.domain="example.com" \
  --set auth.existingSecret="alpha-session-secret"
```

With custom values file:

```bash
helm install alpha ./helm/alpha -f helm/alpha/values-dev.yaml
```

## Authentication Setup

1. Deploy the `KeyRAAccessControl` contract to your Ethereum/Autonity network
2. Create a Kubernetes secret for the session signing key:
   ```bash
   kubectl create secret generic alpha-session-secret \
     --from-literal=session-secret="$(openssl rand -hex 32)"
   ```
3. Configure the Helm values with your contract address and RPC endpoint

## Security

The chart enforces security best practices:

- Runs as non-root user (65534)
- Read-only root filesystem
- Drops all capabilities
- Uses RuntimeDefault seccomp profile
- No privilege escalation
- Session secrets loaded from Kubernetes Secrets

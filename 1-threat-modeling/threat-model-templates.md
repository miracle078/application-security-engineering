# Threat Model Templates - Reusable Amazon-Scale Frameworks

## Overview
These templates provide systematic approaches to threat modeling different types of Amazon services. Each template is designed to work at Amazon's scale (100M+ users) and focuses on customer trust impact.

---

## Template 1: Web Application with User Data

### Service Architecture Template
```
[Users] → [CloudFront CDN] → [ALB] → [EC2/ECS] → [RDS/DynamoDB]
                                ↓
                         [S3 Storage] ← [Lambda Processing]
                                ↓
                         [ElastiCache] → [CloudWatch Logs]
```

### STRIDE Analysis Framework

#### Spoofing (Identity)
**Standard Threats**:
- User impersonation through stolen credentials
- Service impersonation through certificate attacks
- Cross-account access through confused deputy

**Amazon Scale Considerations**:
- Multiple authentication providers (Cognito, SAML, OAuth)
- Global user base across different regulations
- Service-to-service authentication at microservices scale

**Customer Impact Questions**:
- How many customers affected if authentication bypassed?
- What customer data exposed through identity spoofing?
- Impact on customer trust scores and retention?

**Template Mitigations**:
- Multi-factor authentication with SMS/TOTP
- Certificate pinning and rotation
- AWS IAM roles with least privilege
- Cross-service authentication tokens

#### Tampering (Data Integrity)
**Standard Threats**:
- Data modification in transit (MITM)
- Database tampering through injection
- File corruption in storage systems

**Amazon Scale Considerations**:
- Data consistency across multiple regions
- Integrity verification for petabytes of data
- Real-time tampering detection at high volume

**Template Mitigations**:
- End-to-end encryption with integrity checks
- Database transaction logging and rollback
- S3 object versioning and checksums
- CloudTrail for audit trails

#### Repudiation (Non-repudiation)
**Standard Threats**:
- Users denying actions they performed
- Admins denying configuration changes
- System actions without audit trails

**Template Mitigations**:
- Comprehensive logging to CloudWatch
- Digital signatures for critical actions
- Immutable audit logs with timestamps
- Legal compliance documentation

#### Information Disclosure (Confidentiality)
**Standard Threats**:
- Unauthorized data access
- Data leakage through error messages
- Metadata exposure in responses

**Amazon Scale Considerations**:
- Classification of data by sensitivity level
- Regional data residency requirements
- Customer PII protection across services

**Template Mitigations**:
- Encryption at rest and in transit
- IAM policies with data classification
- VPC network isolation
- DLP tools for sensitive data detection

#### Denial of Service (Availability)
**Standard Threats**:
- Resource exhaustion attacks
- Application-layer DoS
- Infrastructure overload

**Amazon Scale Considerations**:
- Auto-scaling under attack conditions
- Global load distribution
- Cost implications of DoS mitigation

**Template Mitigations**:
- AWS WAF with rate limiting
- Auto-scaling groups with limits
- CloudFront caching and DDoS protection
- Circuit breakers and graceful degradation

#### Elevation of Privilege (Authorization)
**Standard Threats**:
- Privilege escalation through bugs
- Role-based access bypass
- Administrative function abuse

**Template Mitigations**:
- Principle of least privilege
- Regular access reviews and rotation
- Privileged access monitoring
- Just-in-time access provisioning

---

## Template 2: API Gateway Service

### Service Architecture Template
```
[Mobile/Web Apps] → [API Gateway] → [Lambda Functions]
                                        ↓
                              [DynamoDB/RDS] ← [SQS/SNS]
                                        ↓
                              [ElastiCache] → [CloudWatch]
```

### API-Specific Threat Categories

#### Authentication & Authorization
**Interview Questions to Address**:
- "How would you secure API keys for 1M+ developers?"
- "What's your approach to rate limiting at global scale?"
- "How do you handle API versioning for security?"

**Template Response Framework**:
1. **Current State Analysis**: Token management, rate limiting, versioning
2. **Scale Challenges**: Key distribution, global rate limiting, backward compatibility
3. **Proposed Solution**: AWS Cognito, API Gateway throttling, versioned security policies
4. **Customer Impact**: Developer experience, API reliability, security transparency

#### Data Validation & Sanitization
**Template Threats**:
- Injection attacks through API parameters
- Schema poisoning attacks
- Oversized payload DoS

**Amazon-Scale Mitigations**:
- API Gateway request validation
- Lambda input sanitization
- WAF rules for common attack patterns
- CloudWatch metrics for anomaly detection

---

## Template 3: Microservices Architecture

### Service Architecture Template
```
[API Gateway] → [Service Mesh] → [Microservice Pods]
                      ↓              ↓
              [Service Discovery] → [Database per Service]
                      ↓
              [Message Queue] → [Monitoring/Logging]
```

### Microservices-Specific Considerations

#### Service-to-Service Communication
**Threat Model Questions**:
- How do you ensure service identity verification?
- What happens when one service is compromised?
- How do you handle cascading security failures?

**Template Analysis**:
- **Trust Boundaries**: Between services, within clusters, across regions
- **Communication Security**: mTLS, service mesh security, certificate management
- **Failure Isolation**: Circuit breakers, bulkhead patterns, security boundaries

#### Data Flow Security
**Template Approach**:
1. **Map Data Flows**: Identify all service interactions and data paths
2. **Classify Data**: Sensitive customer data, internal metadata, public information
3. **Apply Controls**: Encryption, access controls, data loss prevention
4. **Monitor Flows**: Real-time monitoring, anomaly detection, compliance reporting

---

## Template 4: Data Processing Pipeline

### Service Architecture Template
```
[Data Sources] → [Kinesis/Kafka] → [Lambda/Glue] → [Data Lake]
                        ↓              ↓              ↓
               [Real-time Analytics] → [EMR] → [Redshift/Athena]
```

### Data Pipeline Threat Model

#### Data Ingestion Security
**Template Threats**:
- Malicious data injection
- Data source impersonation
- Pipeline resource exhaustion

**Amazon-Scale Considerations**:
- Terabytes of data per hour
- Multiple data source validation
- Real-time threat detection in streams

#### Data Processing Security
**Template Analysis Framework**:
1. **Input Validation**: Schema validation, data type checking, range validation
2. **Processing Isolation**: Container security, resource limits, network isolation
3. **Output Verification**: Data quality checks, integrity validation, audit trails
4. **Error Handling**: Secure error logging, failure recovery, data replay

---

## Quick Reference Interview Templates

### 5-Minute Threat Model Template
**Use this structure for rapid threat modeling in interviews**:

1. **Architecture (60 seconds)**:
   - Draw high-level components
   - Identify trust boundaries
   - Note data flows

2. **STRIDE Analysis (3 minutes)**:
   - One threat per category
   - Focus on highest impact
   - Include customer impact

3. **Mitigations (90 seconds)**:
   - AWS-native solutions
   - Scalable implementations
   - Cost-effective approaches

### Customer Impact Statement Templates

**For Data Breaches**:
> "This threat could expose [X] customer records, representing $[Y] potential breach costs and [Z]% customer churn based on industry benchmarks."

**For Service Disruption**:
> "This availability threat could affect [X] million customers, causing $[Y] hourly revenue loss and [Z]% decrease in customer satisfaction scores."

**For Compliance Violations**:
> "This control failure could trigger [X] regulatory violations, resulting in up to $[Y] fines and [Z] months of remediation work."

---

## Amazon-Specific Threat Model Considerations

### Scale Factors to Always Include
- **200M+ Amazon Prime members** globally
- **99.99% availability** requirements for customer-facing services
- **Multi-region deployment** with data residency requirements
- **Petabyte-scale data** processing capabilities
- **Millisecond latency** requirements for customer experience

### AWS Service Integration Points
- **Security Hub**: Centralized finding aggregation
- **GuardDuty**: Threat detection integration
- **CloudTrail**: Audit and compliance logging
- **Config**: Configuration compliance monitoring
- **WAF**: Application layer protection

### Customer Trust Metrics
- **Net Promoter Score** impact of security incidents
- **Customer retention rates** post-security events
- **Support ticket volume** related to security concerns
- **Brand reputation scores** in security surveys

This template library ensures consistent, thorough threat modeling that demonstrates Amazon-scale thinking and customer-centric security approaches required for the Application Security Engineer role.
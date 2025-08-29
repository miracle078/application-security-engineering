# Threat Modeling - Core Amazon Responsibility

## Job Requirement
> "Creating, updating, and maintaining threat models for a wide variety of software projects."

## What Amazon Tests
- **Systematic approach**: Can you follow STRIDE or similar methodology?
- **Scale considerations**: Will your analysis work for Amazon's global services?
- **Customer impact focus**: How do security threats affect customer trust?
- **Business risk communication**: Can you explain threats to non-technical stakeholders?

## Contents
- 📋 [`amazon-scale-threat-modeling.md`](./amazon-scale-threat-modeling.md) - Complete STRIDE methodology for 100M+ user scenarios
- 📊 [`threat-model-templates.md`](./threat-model-templates.md) - Reusable templates for web apps, APIs, microservices
- 💰 [`customer-impact-analysis.md`](./customer-impact-analysis.md) - Business impact quantification frameworks
- 🎯 [`practice-scenarios.md`](./practice-scenarios.md) - Prime Video, Alexa, AWS Marketplace scenarios
- 🎭 [`file-upload-threat-model.md`](./file-upload-threat-model.md) - **RECRUITER'S SPECIFIC SCENARIO**

## 🚀 Start Here - Quick Practice
**Scenario**: "Threat model a file upload service for Amazon Prime members"
- **⏰ Time Limit**: 15-20 minutes  
- **📋 Framework**: Use [file-upload-threat-model.md](./file-upload-threat-model.md) as reference
- **🎯 Expected Output**: STRIDE analysis + customer impact + AWS mitigations
- **💡 Pro Tip**: Start with architecture diagram, then systematic STRIDE analysis

## Practice Flow
1. **Read scenario** (2 minutes) - Understand requirements and scale
2. **Draw architecture** (3 minutes) - Components and data flows  
3. **STRIDE analysis** (10 minutes) - Systematic threat identification
4. **Customer impact** (3 minutes) - Business quantification
5. **AWS mitigations** (2 minutes) - Scalable solutions

## Success Metrics
- [ ] Can complete threat model in interview timeframe
- [ ] Demonstrates systematic methodology
- [ ] Shows scale thinking (millions of users)
- [ ] Connects threats to customer impact
- [ ] Proposes feasible AWS-based mitigations
# CloudLens — AWS Security & Cost Optimization Auditor

CloudLens is a **read-only AWS auditing project** focused on identifying security risks, governance gaps, unused resources, and cost-optimization opportunities across cloud environments.

The project was built as a hands-on portfolio project to combine **AWS, information security, automation, risk analysis, and technical reporting**.

## Why CloudLens

Cloud environments can grow quickly and accumulate issues such as:

- overly permissive IAM access;
- publicly exposed resources;
- weak security-group rules;
- missing logging or monitoring;
- unused or underutilized resources;
- unnecessary cloud spend;
- inconsistent governance practices.

CloudLens structures these checks into a repeatable audit workflow and translates technical findings into clear remediation priorities.

## Core capabilities

- AWS environment inventory and audit
- Security and governance checks
- IAM and access-risk analysis
- EC2 and Security Group review
- S3 exposure and configuration review
- EBS / resource-efficiency checks
- Logging and monitoring visibility
- Prioritized findings
- Remediation recommendations
- Estimated cost-saving opportunities
- Business-friendly reporting

## Security model

CloudLens is designed around **least privilege and read-only access**.

The intended access model uses:

- AWS IAM Role
- temporary credentials
- restricted permissions
- External ID concepts for cross-account access
- no destructive actions
- no modification of the audited environment

The auditor is intended to inspect configuration metadata rather than application data.

## High-level workflow

```text
AWS Account
    ↓
Read-only IAM Role
    ↓
AWS APIs
    ↓
Resource & Security Checks
    ↓
Risk / Cost Findings
    ↓
Prioritization
    ↓
Remediation Guidance
    ↓
Audit Report
```

## Example finding

```text
Finding: Security Group allows inbound SSH from 0.0.0.0/0
Severity: High
Service: EC2 / VPC

Risk:
The resource may be reachable from any public IP address.

Recommendation:
Restrict port 22 access to approved administrative networks or use
a managed access mechanism such as AWS Systems Manager Session Manager.
```

## Technologies and concepts

- Python
- AWS APIs
- IAM
- EC2
- S3
- EBS
- Security Groups
- CloudTrail
- CloudWatch
- cloud security fundamentals
- least privilege
- risk assessment
- security findings
- cost optimization
- technical documentation

## What I learned

Building CloudLens helped me practice how to:

- convert security concepts into automated checks;
- reason about AWS permissions and least privilege;
- identify and prioritize cloud risks;
- organize technical findings for decision-making;
- connect security recommendations with operational and cost impact;
- communicate technical issues in a concise, business-friendly format.

## Project status

CloudLens is a **portfolio / learning project** and should not be treated as a replacement for a complete production cloud-security platform or formal compliance audit.

The project continues to evolve as I deepen my studies in **Cloud, Information Security, DevOps, automation, and governance**.

## Author

**Carlos Henrique Braatz Lautert**  
Electrical Engineering — Federal University of Santa Catarina (UFSC)

GitHub: [carloslautert](https://github.com/carloslautert)  
LinkedIn: [linkedin.com/in/carloshbl](https://linkedin.com/in/carloshbl)

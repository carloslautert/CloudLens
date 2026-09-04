# CloudLens — AWS Security & Cost Optimization Auditor

CloudLens is a **read-only AWS auditing project** focused on identifying security risks, governance gaps, unused resources, and cost-optimization opportunities across cloud environments.

It is a hands-on portfolio project combining **AWS, Information Security, automation, risk analysis, and technical reporting**.

## What it does

CloudLens inspects AWS configuration metadata and can flag issues such as:

- IAM console users without MFA
- old IAM access keys
- public SSH/RDP access in Security Groups
- publicly accessible RDS instances
- public S3 bucket policies
- missing active CloudTrail logging
- unattached EBS volumes
- unassociated Elastic IPs
- stopped or underutilized EC2 instances

It also produces a structured JSON result and can generate a simple HTML report with prioritized findings and remediation guidance.

## Security model

The project is designed around **least privilege and read-only access**.

It supports:

- local AWS credentials for testing
- cross-account access through an AWS IAM Role
- temporary STS credentials
- optional External ID
- no create/update/delete AWS actions
- configuration metadata inspection only

> Never commit AWS credentials, private keys or real client audit outputs to this repository.

## High-level flow

```text
AWS Account
    ↓
Read-only IAM Role / local AWS profile
    ↓
AWS APIs
    ↓
Security + Governance + Cost Checks
    ↓
JSON Findings
    ↓
HTML Report
```

## Project structure

```text
CloudLens/
├── audit.py
├── generate_report.py
├── requirements.txt
├── examples/
│   └── sample_audit_result.json
└── README.md
```

## Quick start

### 1. Create a virtual environment

```bash
python -m venv .venv
```

Activate it using the command appropriate for your operating system.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run an audit

Using your local AWS credentials:

```bash
python audit.py --regions us-east-1 --output output/audit_result.json
```

Across available AWS regions:

```bash
python audit.py --regions all --output output/audit_result.json
```

Using a cross-account read-only role:

```bash
python audit.py \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/CloudLensAuditRole \
  --external-id YOUR_EXTERNAL_ID \
  --regions all \
  --output output/audit_result.json
```

### 4. Generate the HTML report

```bash
python generate_report.py \
  output/audit_result.json \
  --company "Demo Company" \
  --auditor-name "Carlos Henrique Braatz Lautert"
```

## Synthetic example

A sanitized demo result is available at:

`examples/sample_audit_result.json`

It contains only fictitious identifiers and is safe to inspect publicly.

## Example finding

```text
Finding: Public SSH access
Severity: High
Service: EC2 / VPC

Risk:
TCP port 22 is reachable from the public internet.

Recommendation:
Restrict the rule to approved administrative networks or use
AWS Systems Manager Session Manager where appropriate.
```

## Technologies and concepts

- Python
- boto3
- AWS APIs
- IAM / STS
- EC2
- EBS
- Security Groups
- S3
- RDS
- CloudTrail
- CloudWatch
- least privilege
- cloud security fundamentals
- risk assessment
- technical reporting
- cost optimization

## Important limitations

CloudLens is a **portfolio / learning project**. It is not a replacement for:

- a formal ISO 27001 audit
- a compliance assessment
- a penetration test
- a CSPM / CNAPP production platform
- AWS Security Hub or other enterprise security tooling

Cost estimates are illustrative and should be validated against current AWS pricing before decisions are made.

## Author

**Carlos Henrique Braatz Lautert**  
Electrical Engineering — Federal University of Santa Catarina (UFSC)

GitHub: [carloslautert](https://github.com/carloslautert)  
LinkedIn: [linkedin.com/in/carloshbl](https://linkedin.com/in/carloshbl)

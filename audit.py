"""CloudLens: read-only AWS security, governance and cost audit.

The tool inspects configuration metadata through AWS APIs and writes a JSON
report. It does not create, update or delete AWS resources.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    resource_id: str
    resource_type: str
    region: str
    description: str
    recommendation: str
    estimated_monthly_cost_brl: float = 0.0
    extra: dict = field(default_factory=dict)


class CloudAuditor:
    """Collect configuration findings from an AWS account using read-only APIs."""

    USD_TO_BRL = 5.0

    def __init__(
        self,
        role_arn: str | None = None,
        external_id: str | None = None,
        regions: list[str] | None = None,
    ) -> None:
        requested = regions or ["us-east-1"]
        self.errors: list[dict] = []
        self.session = self._build_session(role_arn, external_id)
        self.account_id = self._account_id()
        self.regions = self._all_regions() if requested == ["all"] else requested
        self.findings: list[Finding] = []
        self.scope = {
            "regions": len(self.regions),
            "ec2_instances": 0,
            "ebs_volumes": 0,
            "security_groups": 0,
            "elastic_ips": 0,
            "rds_instances": 0,
            "s3_buckets": 0,
            "iam_users": 0,
            "access_keys": 0,
            "cloudtrails": 0,
        }

    def _build_session(self, role_arn: str | None, external_id: str | None) -> boto3.Session:
        if not role_arn:
            return boto3.Session()

        kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": "CloudLensAuditSession",
            "DurationSeconds": 3600,
        }
        if external_id:
            kwargs["ExternalId"] = external_id

        sts = boto3.client("sts", region_name="us-east-1")
        creds = sts.assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def _account_id(self) -> str:
        try:
            return self.session.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
        except Exception as exc:
            self._error("STS account identity", exc)
            return "unknown"

    def _all_regions(self) -> list[str]:
        try:
            response = self.session.client("ec2", region_name="us-east-1").describe_regions(AllRegions=False)
            return sorted(r["RegionName"] for r in response.get("Regions", [])) or ["us-east-1"]
        except Exception as exc:
            self._error("List AWS regions", exc)
            return ["us-east-1"]

    def _error(self, check: str, exc: Exception) -> None:
        message = str(exc)
        if isinstance(exc, ClientError):
            message = exc.response.get("Error", {}).get("Code", "AWS API error")
        self.errors.append({"check": check, "message": message[:180]})

    def _add(self, **kwargs) -> None:
        self.findings.append(Finding(**kwargs))

    def _safe(self, name: str, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as exc:
            self._error(name, exc)

    def check_ec2(self, region: str, cpu_threshold: float = 10.0, lookback_days: int = 14) -> None:
        ec2 = self.session.client("ec2", region_name=region)
        cw = self.session.client("cloudwatch", region_name=region)
        reservations: list[dict] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            reservations.extend(page.get("Reservations", []))

        instances = [i for r in reservations for i in r.get("Instances", [])]
        self.scope["ec2_instances"] += len(instances)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)

        hourly_usd = {
            "t3.micro": 0.0104,
            "t3.small": 0.0208,
            "t3.medium": 0.0416,
            "t3.large": 0.0832,
            "m5.large": 0.096,
            "c5.large": 0.085,
        }

        for instance in instances:
            iid = instance["InstanceId"]
            state = instance.get("State", {}).get("Name", "unknown")
            itype = instance.get("InstanceType", "unknown")

            if state == "stopped":
                self._add(
                    category="cost",
                    severity="medium",
                    title="Stopped EC2 instance",
                    resource_id=iid,
                    resource_type="EC2 Instance",
                    region=region,
                    description="The instance is stopped; attached EBS volumes may still generate recurring cost.",
                    recommendation="Confirm whether the instance is still required. Snapshot important data before removing unused resources.",
                )
                continue

            if state != "running":
                continue

            metrics = cw.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=["Average"],
            ).get("Datapoints", [])
            if not metrics:
                continue
            avg_cpu = sum(float(x["Average"]) for x in metrics) / len(metrics)
            if avg_cpu < cpu_threshold:
                estimated = round(hourly_usd.get(itype, 0.0) * 730 * self.USD_TO_BRL, 2)
                self._add(
                    category="cost",
                    severity="medium",
                    title="Low-utilization EC2 instance",
                    resource_id=iid,
                    resource_type="EC2 Instance",
                    region=region,
                    description=f"Average CPU utilization was approximately {avg_cpu:.1f}% over the last {lookback_days} days.",
                    recommendation="Review rightsizing or scheduling options before changing production capacity.",
                    estimated_monthly_cost_brl=estimated,
                    extra={"instance_type": itype, "average_cpu_percent": round(avg_cpu, 1)},
                )

    def check_ebs(self, region: str) -> None:
        ec2 = self.session.client("ec2", region_name=region)
        volumes = ec2.describe_volumes().get("Volumes", [])
        self.scope["ebs_volumes"] += len(volumes)
        for volume in volumes:
            if volume.get("State") != "available":
                continue
            size = int(volume.get("Size", 0))
            estimated = round(size * 0.08 * self.USD_TO_BRL, 2)
            self._add(
                category="cost",
                severity="medium",
                title="Unattached EBS volume",
                resource_id=volume["VolumeId"],
                resource_type="EBS Volume",
                region=region,
                description=f"The {size} GiB volume is not attached to an EC2 instance and may be generating avoidable cost.",
                recommendation="Verify ownership and retention needs. Create a snapshot before deleting an unused volume.",
                estimated_monthly_cost_brl=estimated,
            )

    def check_security_groups(self, region: str) -> None:
        ec2 = self.session.client("ec2", region_name=region)
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        self.scope["security_groups"] += len(groups)
        sensitive_ports = {22: "SSH", 3389: "RDP"}
        for sg in groups:
            for rule in sg.get("IpPermissions", []):
                start = rule.get("FromPort")
                end = rule.get("ToPort")
                if start is None or end is None:
                    continue
                public = any(x.get("CidrIp") == "0.0.0.0/0" for x in rule.get("IpRanges", []))
                public |= any(x.get("CidrIpv6") == "::/0" for x in rule.get("Ipv6Ranges", []))
                if not public:
                    continue
                for port, label in sensitive_ports.items():
                    if start <= port <= end:
                        self._add(
                            category="security",
                            severity="high",
                            title=f"Public {label} access",
                            resource_id=sg["GroupId"],
                            resource_type="Security Group",
                            region=region,
                            description=f"TCP port {port} is reachable from the public internet.",
                            recommendation="Restrict the rule to approved networks or use AWS Systems Manager Session Manager where appropriate.",
                            extra={"port": port},
                        )

    def check_elastic_ips(self, region: str) -> None:
        ec2 = self.session.client("ec2", region_name=region)
        addresses = ec2.describe_addresses().get("Addresses", [])
        self.scope["elastic_ips"] += len(addresses)
        for address in addresses:
            if address.get("AssociationId") or address.get("InstanceId") or address.get("NetworkInterfaceId"):
                continue
            rid = address.get("AllocationId") or address.get("PublicIp", "unknown")
            self._add(
                category="cost",
                severity="low",
                title="Unassociated Elastic IP",
                resource_id=rid,
                resource_type="Elastic IP",
                region=region,
                description="The Elastic IP is not associated with a resource and may generate charges.",
                recommendation="Release unused Elastic IP addresses after confirming they are not reserved for an operational need.",
            )

    def check_rds(self, region: str) -> None:
        rds = self.session.client("rds", region_name=region)
        instances = rds.describe_db_instances().get("DBInstances", [])
        self.scope["rds_instances"] += len(instances)
        for db in instances:
            if db.get("PubliclyAccessible"):
                self._add(
                    category="security",
                    severity="high",
                    title="Publicly accessible RDS instance",
                    resource_id=db.get("DBInstanceIdentifier", "unknown"),
                    resource_type="RDS Instance",
                    region=region,
                    description="The database instance is configured as publicly accessible.",
                    recommendation="Validate the requirement and prefer private subnets plus controlled application or administrative access.",
                )

    def check_s3(self) -> None:
        s3 = self.session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        self.scope["s3_buckets"] = len(buckets)
        for bucket in buckets:
            name = bucket["Name"]
            try:
                status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
                if status.get("IsPublic"):
                    self._add(
                        category="security",
                        severity="critical",
                        title="Public S3 bucket policy",
                        resource_id=name,
                        resource_type="S3 Bucket",
                        region="global",
                        description="AWS reports the bucket policy as public.",
                        recommendation="Review the bucket policy, Block Public Access settings and business requirement before restricting access.",
                    )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code not in {"NoSuchBucketPolicy", "AccessDenied"}:
                    self._error(f"S3 policy status: {name}", exc)

    def check_iam(self, age_days: int = 90) -> None:
        iam = self.session.client("iam")
        users = iam.list_users().get("Users", [])
        self.scope["iam_users"] = len(users)
        cutoff = datetime.now(timezone.utc) - timedelta(days=age_days)

        for user in users:
            name = user["UserName"]
            mfa = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
            try:
                iam.get_login_profile(UserName=name)
                has_console = True
            except ClientError as exc:
                has_console = exc.response.get("Error", {}).get("Code") != "NoSuchEntity"
            if has_console and not mfa:
                self._add(
                    category="security",
                    severity="high",
                    title="IAM console user without MFA",
                    resource_id=name,
                    resource_type="IAM User",
                    region="global",
                    description="The IAM user has console access but no MFA device was found.",
                    recommendation="Enable MFA and review whether console access is still necessary.",
                )

            keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
            self.scope["access_keys"] += len(keys)
            for key in keys:
                created = key.get("CreateDate")
                if key.get("Status") == "Active" and created and created < cutoff:
                    self._add(
                        category="security",
                        severity="medium",
                        title="Old IAM access key",
                        resource_id=key.get("AccessKeyId", "unknown")[-4:].rjust(8, "*"),
                        resource_type="IAM Access Key",
                        region="global",
                        description=f"An active access key is older than {age_days} days.",
                        recommendation="Confirm whether the key is still needed and rotate or remove it according to the organization's credential policy.",
                        extra={"user": name, "age_threshold_days": age_days},
                    )

    def check_cloudtrail(self) -> None:
        client = self.session.client("cloudtrail", region_name="us-east-1")
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
        self.scope["cloudtrails"] = len(trails)
        logging = False
        for trail in trails:
            try:
                if client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
                    logging = True
                    break
            except Exception as exc:
                self._error("CloudTrail status", exc)
        if not logging:
            self._add(
                category="governance",
                severity="high",
                title="No active CloudTrail logging found",
                resource_id="account",
                resource_type="CloudTrail",
                region="global",
                description="The audit did not find an active CloudTrail trail among the trails it could inspect.",
                recommendation="Enable and protect CloudTrail logging appropriate to the account's governance and incident-response requirements.",
            )

    def run(self) -> dict:
        for region in self.regions:
            self._safe(f"EC2 ({region})", self.check_ec2, region)
            self._safe(f"EBS ({region})", self.check_ebs, region)
            self._safe(f"Security Groups ({region})", self.check_security_groups, region)
            self._safe(f"Elastic IPs ({region})", self.check_elastic_ips, region)
            self._safe(f"RDS ({region})", self.check_rds, region)

        self._safe("S3", self.check_s3)
        self._safe("IAM", self.check_iam)
        self._safe("CloudTrail", self.check_cloudtrail)

        by_severity: dict[str, int] = {}
        for finding in self.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        return {
            "account_id": self.account_id,
            "audit_date": datetime.now(timezone.utc).isoformat(),
            "regions": self.regions,
            "scope": self.scope,
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "total_estimated_savings_brl": round(sum(f.estimated_monthly_cost_brl for f in self.findings), 2),
            "findings": [asdict(f) for f in self.findings],
            "errors": self.errors,
            "disclaimer": "Cost estimates are illustrative and should be validated against current AWS pricing before decisions are made.",
        }


def save_json(data: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, default=str)


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudLens — read-only AWS security and cost audit")
    parser.add_argument("--role-arn", help="Optional cross-account IAM Role ARN")
    parser.add_argument("--external-id", help="Optional External ID used with AssumeRole")
    parser.add_argument("--regions", nargs="+", default=["us-east-1"], help="AWS regions or: all")
    parser.add_argument("--output", default="output/audit_result.json", help="Output JSON path")
    args = parser.parse_args()

    auditor = CloudAuditor(args.role_arn, args.external_id, args.regions)
    result = auditor.run()
    save_json(result, args.output)
    print(f"CloudLens finished: {result['total_findings']} finding(s). JSON: {args.output}")


if __name__ == "__main__":
    main()

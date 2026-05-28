"""
checkers/rds_checker.py
Amazon RDS 보안 점검

점검 항목:
  RDS-01  퍼블릭 접근 허용 여부
  RDS-02  기본/약한 마스터 계정명
  RDS-03  저장 데이터 암호화 미적용
  RDS-04  보안 그룹 과다 개방 (0.0.0.0/0)
  RDS-05  자동 백업 보존 기간
  RDS-06  SSL/TLS 전송 암호화 강제 여부
  RDS-07  CloudWatch 로그 내보내기 설정
"""

import boto3
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, PASS, FAIL, WARN

WEAK_USERNAMES       = {"admin", "root", "postgres", "mysql", "oracle", "sa", "master", "user", "test", "db"}
BACKUP_WARN_DAYS     = 7
BACKUP_OK_DAYS       = 30


class RDSChecker(BaseChecker):
    SERVICE_NAME = "RDS"

    def run(self) -> ServiceReport:
        report     = ServiceReport(service=self.SERVICE_NAME)
        rds_client = boto3.client("rds", region_name=self.region)
        ec2_client = boto3.client("ec2", region_name=self.region)

        try:
            instances = rds_client.describe_db_instances().get("DBInstances", [])
        except Exception as e:
            return report  # 권한 없음 등

        if not instances:
            return report

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            report.results.append(self._check_public_access(db))
            report.results.append(self._check_master_username(db))
            report.results.append(self._check_storage_encryption(db))
            report.results.append(self._check_security_groups(db, ec2_client))
            report.results.append(self._check_backup_retention(db))
            report.results.append(self._check_ssl_tls(db, rds_client))
            report.results.append(self._check_cloudwatch_logs(db))

        return report

    # ── 개별 점검 ─────────────────────────────────────

    def _check_public_access(self, db: dict):
        db_id  = db["DBInstanceIdentifier"]
        public = db.get("PubliclyAccessible", False)
        return self._make_result(
            check_id="RDS-01", name="퍼블릭 접근 허용",
            severity=HIGH, resource_id=db_id,
            status=FAIL if public else PASS,
            detail=f"PubliclyAccessible = {public}",
            remediation=(
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--no-publicly-accessible --apply-immediately"
            ) if public else "조치 불필요",
        )

    def _check_master_username(self, db: dict):
        db_id    = db["DBInstanceIdentifier"]
        username = db.get("MasterUsername", "").lower()
        is_weak  = username in WEAK_USERNAMES
        return self._make_result(
            check_id="RDS-02", name="기본/약한 마스터 계정명 사용",
            severity=HIGH, resource_id=db_id,
            status=FAIL if is_weak else PASS,
            detail=f"MasterUsername = '{username}'",
            remediation="Secrets Manager 연동 후 강력한 비밀번호로 교체, 애플리케이션별 최소 권한 계정 분리" if is_weak else "조치 불필요",
        )

    def _check_storage_encryption(self, db: dict):
        db_id     = db["DBInstanceIdentifier"]
        encrypted = db.get("StorageEncrypted", False)
        kms       = db.get("KmsKeyId", "N/A")
        return self._make_result(
            check_id="RDS-03", name="저장 데이터 암호화 미적용",
            severity=HIGH, resource_id=db_id,
            status=PASS if encrypted else FAIL,
            detail=f"StorageEncrypted={encrypted}, KmsKeyId={kms}",
            remediation=(
                "기존 DB 소급 불가 → 암호화 스냅샷 복사 후 새 인스턴스 복원:\n"
                f"aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> "
                "--target-db-snapshot-identifier <snap-enc> --kms-key-id alias/aws/rds"
            ) if not encrypted else "조치 불필요",
        )

    def _check_security_groups(self, db: dict, ec2_client):
        db_id      = db["DBInstanceIdentifier"]
        sg_ids     = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
        open_rules = []
        try:
            sgs = ec2_client.describe_security_groups(GroupIds=sg_ids).get("SecurityGroups", [])
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    fp, tp = rule.get("FromPort", 0), rule.get("ToPort", 0)
                    for r in rule.get("IpRanges", []):
                        if r.get("CidrIp") == "0.0.0.0/0":
                            open_rules.append(f"SG={sg['GroupId']} port={fp}-{tp} 0.0.0.0/0")
                    for r in rule.get("Ipv6Ranges", []):
                        if r.get("CidrIpv6") == "::/0":
                            open_rules.append(f"SG={sg['GroupId']} port={fp}-{tp} ::/0")
        except Exception:
            pass

        return self._make_result(
            check_id="RDS-04", name="보안 그룹 과다 개방",
            severity=HIGH, resource_id=db_id,
            status=FAIL if open_rules else PASS,
            detail="; ".join(open_rules) if open_rules else "전체 IP 허용 규칙 없음",
            remediation=(
                "aws ec2 revoke-security-group-ingress --group-id <sg-id> "
                "--protocol tcp --port 3306 --cidr 0.0.0.0/0"
            ) if open_rules else "조치 불필요",
        )

    def _check_backup_retention(self, db: dict):
        db_id  = db["DBInstanceIdentifier"]
        period = db.get("BackupRetentionPeriod", 0)
        if period == 0:
            status, detail = FAIL, "BackupRetentionPeriod=0 (자동 백업 비활성화)"
        elif period < BACKUP_WARN_DAYS:
            status, detail = WARN, f"BackupRetentionPeriod={period}일 (권장 7일 이상)"
        elif period < BACKUP_OK_DAYS:
            status, detail = WARN, f"BackupRetentionPeriod={period}일 (최적 30일 이상 권장)"
        else:
            status, detail = PASS, f"BackupRetentionPeriod={period}일"
        return self._make_result(
            check_id="RDS-05", name="자동 백업 보존 기간",
            severity=MEDIUM, resource_id=db_id,
            status=status, detail=detail,
            remediation=(
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--backup-retention-period 30 --apply-immediately"
            ) if status != PASS else "조치 불필요",
        )

    def _check_ssl_tls(self, db: dict, rds_client):
        db_id   = db["DBInstanceIdentifier"]
        engine  = db.get("Engine", "").lower()
        pg_name = next((pg["DBParameterGroupName"] for pg in db.get("DBParameterGroups", [])), None)

        if not pg_name or pg_name.startswith("default."):
            return self._make_result(
                check_id="RDS-06", name="SSL/TLS 전송 암호화",
                severity=MEDIUM, resource_id=db_id, status=WARN,
                detail=f"기본 파라미터 그룹 사용 중 ({pg_name}) → SSL 강제 설정 불가",
                remediation="커스텀 파라미터 그룹 생성 후 MySQL: require_secure_transport=ON / PostgreSQL: rds.force_ssl=1",
            )
        try:
            param_name = "require_secure_transport" if "mysql" in engine or "mariadb" in engine else "rds.force_ssl"
            params     = {
                p["ParameterName"]: p.get("ParameterValue", "")
                for p in rds_client.describe_db_parameters(
                    DBParameterGroupName=pg_name, Source="user"
                ).get("Parameters", [])
            }
            value      = params.get(param_name, "NOT_SET")
            ssl_on     = value in ("1", "ON", "on", "true")
            return self._make_result(
                check_id="RDS-06", name="SSL/TLS 전송 암호화",
                severity=MEDIUM, resource_id=db_id,
                status=PASS if ssl_on else FAIL,
                detail=f"{param_name}={value}",
                remediation=(
                    f"aws rds modify-db-parameter-group --db-parameter-group-name {pg_name} "
                    f"--parameters ParameterName={param_name},ParameterValue=ON,ApplyMethod=immediate"
                ) if not ssl_on else "조치 불필요",
            )
        except Exception as e:
            return self._make_result(
                check_id="RDS-06", name="SSL/TLS 전송 암호화",
                severity=MEDIUM, resource_id=db_id, status=WARN,
                detail=f"파라미터 조회 실패: {e}",
                remediation="IAM 권한(rds:DescribeDBParameters) 확인 필요",
            )

    def _check_cloudwatch_logs(self, db: dict):
        db_id       = db["DBInstanceIdentifier"]
        engine      = db.get("Engine", "").lower()
        enabled     = set(db.get("EnabledCloudwatchLogsExports", []))
        recommended = {"audit", "error", "general", "slowquery"} if "mysql" in engine or "mariadb" in engine \
                      else {"postgresql", "upgrade"} if "postgres" in engine else {"error"}
        missing     = recommended - enabled

        if not enabled:
            status, detail = FAIL, "로그 내보내기 미설정"
        elif missing:
            status, detail = WARN, f"누락 로그: {sorted(missing)}"
        else:
            status, detail = PASS, f"활성화: {sorted(enabled)}"

        return self._make_result(
            check_id="RDS-07", name="CloudWatch 로그 설정",
            severity=MEDIUM, resource_id=db_id,
            status=status, detail=detail,
            remediation=(
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                '--cloudwatch-logs-export-configuration \'{"EnableLogTypes":["audit","error","general","slowquery"]}\' '
                "--apply-immediately"
            ) if status != PASS else "조치 불필요",
        )

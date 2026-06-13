"""
checkers/ec2_checker.py
Amazon EC2 보안 점검

점검 항목:
  EC2-01  보안 그룹 인바운드 규칙 과다 허용 (0.0.0.0/0)
  EC2-02  IMDSv2 미강제 (HttpTokens != required)
  EC2-03  EBS 볼륨 암호화 누락
  EC2-04  IAM 역할 미할당 (IamInstanceProfile 없음)
  EC2-05  User Data 내 민감 정보 포함 여부
"""

import base64, boto3
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, LOW, PASS, FAIL, WARN

SENSITIVE_KEYWORDS = ["password", "secret", "access_key", "token", "private_key"]


class EC2Checker(BaseChecker):
    SERVICE_NAME = "EC2"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        ec2    = boto3.client("ec2", region_name=self.region)

        report.results += self._check_open_security_groups(ec2)  # EC2-01
        report.results += self._check_imdsv2(ec2)                # EC2-02
        report.results += self._check_ebs_encryption(ec2)        # EC2-03
        report.results += self._check_iam_role(ec2)              # EC2-04
        report.results += self._check_user_data(ec2)             # EC2-05

        if not report.results:
            report.results.append(self._make_result(
                "EC2-00", "EC2 리소스 존재 여부", HIGH, "ec2",
                WARN, "보안 그룹/인스턴스/볼륨이 모두 0건 조회됨 — 리전 또는 권한 확인 필요",
                f"현재 점검 리전: {self.region} (보안 그룹은 보통 기본값이 항상 존재합니다)"
            ))

        return report

    # ── EC2-01: 보안 그룹 인바운드 0.0.0.0/0 ────────
    def _check_open_security_groups(self, ec2) -> list:
        results = []
        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            for sg in sgs:
                sg_id   = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)
                open_rules = []

                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            fp   = perm.get("FromPort", "All")
                            tp   = perm.get("ToPort",   "All")
                            proto = perm.get("IpProtocol", "All")
                            open_rules.append(f"프로토콜:{proto} 포트:{fp}~{tp}")
                            break  # 동일 규칙 중복 방지

                if open_rules:
                    results.append(self._make_result(
                        check_id="EC2-01",
                        name="보안 그룹 인바운드 과다 허용",
                        severity=HIGH,
                        resource_id=sg_name,
                        status=FAIL,
                        detail=f"0.0.0.0/0 허용 규칙 {len(open_rules)}개: " + " | ".join(open_rules),
                        remediation=f"EC2 → 보안 그룹 → {sg_id} → 인바운드 규칙 편집\n"
                                    f"→ 0.0.0.0/0 규칙 삭제 후 특정 IP 또는 보안 그룹으로 재제한"
                    ))
                else:
                    results.append(self._make_result(
                        check_id="EC2-01",
                        name="보안 그룹 인바운드 과다 허용",
                        severity=HIGH,
                        resource_id=sg_name,
                        status=PASS,
                        detail="0.0.0.0/0 허용 규칙 없음"
                    ))
        except Exception as e:
            results.append(self._make_result(
                check_id="EC2-01",
                name="보안 그룹 인바운드 과다 허용",
                severity=HIGH,
                resource_id="security-groups",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeSecurityGroups 권한 확인"
            ))
        return results

    # ── EC2-02: IMDSv2 강제 여부 ─────────────────────
    def _check_imdsv2(self, ec2) -> list:
        results = []
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            for res in reservations:
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue

                    inst_id    = inst["InstanceId"]
                    http_tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")

                    if http_tokens != "required":
                        results.append(self._make_result(
                            check_id="EC2-02",
                            name="IMDSv2 미강제",
                            severity=HIGH,
                            resource_id=inst_id,
                            status=FAIL,
                            detail=f"HttpTokens={http_tokens} → IMDSv1 허용 상태 (SSRF 공격으로 자격 증명 탈취 위험)",
                            remediation=f"EC2 → 인스턴스 선택 → 작업 → 인스턴스 설정 → 인스턴스 메타데이터 옵션 수정\n"
                                        f"→ IMDSv2를 '필수'로 변경\n"
                                        f"(CLI) aws ec2 modify-instance-metadata-options --instance-id {inst_id} --http-tokens required"
                        ))
                    else:
                        results.append(self._make_result(
                            check_id="EC2-02",
                            name="IMDSv2 미강제",
                            severity=HIGH,
                            resource_id=inst_id,
                            status=PASS,
                            detail=f"HttpTokens=required (IMDSv2 강제 적용 중)"
                        ))
        except Exception as e:
            results.append(self._make_result(
                check_id="EC2-02",
                name="IMDSv2 미강제",
                severity=HIGH,
                resource_id="instances",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeInstances 권한 확인"
            ))
        return results

    # ── EC2-03: EBS 볼륨 암호화 ──────────────────────
    def _check_ebs_encryption(self, ec2) -> list:
        results = []
        try:
            volumes = ec2.describe_volumes().get("Volumes", [])
            for vol in volumes:
                vol_id    = vol["VolumeId"]
                encrypted = vol.get("Encrypted", False)
                state     = vol.get("State", "?")
                size      = vol.get("Size", "?")

                if not encrypted:
                    results.append(self._make_result(
                        check_id="EC2-03",
                        name="EBS 볼륨 암호화 누락",
                        severity=MEDIUM,
                        resource_id=vol_id,
                        status=FAIL,
                        detail=f"암호화 미적용 (상태: {state}, 크기: {size}GB) — 스토리지 침해 시 데이터 즉시 노출",
                        remediation=f"기존 볼륨 소급 불가 → 스냅샷 생성 후 암호화 복사:\n"
                                    f"aws ec2 create-snapshot --volume-id {vol_id}\n"
                                    f"aws ec2 copy-snapshot --source-snapshot-id <snap-id> --encrypted --kms-key-id alias/aws/ebs"
                    ))
                else:
                    results.append(self._make_result(
                        check_id="EC2-03",
                        name="EBS 볼륨 암호화 누락",
                        severity=MEDIUM,
                        resource_id=vol_id,
                        status=PASS,
                        detail=f"암호화 적용됨 (상태: {state}, 크기: {size}GB)"
                    ))
        except Exception as e:
            results.append(self._make_result(
                check_id="EC2-03",
                name="EBS 볼륨 암호화 누락",
                severity=MEDIUM,
                resource_id="volumes",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeVolumes 권한 확인"
            ))
        return results

    # ── EC2-04: IAM 역할 미할당 ───────────────────────
    def _check_iam_role(self, ec2) -> list:
        results = []
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            for res in reservations:
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue

                    inst_id = inst["InstanceId"]
                    name    = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        "이름 없음"
                    )

                    if "IamInstanceProfile" not in inst:
                        results.append(self._make_result(
                            check_id="EC2-04",
                            name="IAM 역할 미할당",
                            severity=HIGH,
                            resource_id=f"{inst_id} ({name})",
                            status=FAIL,
                            detail="IamInstanceProfile 없음 → 액세스 키를 인스턴스 내부에 직접 저장할 위험",
                            remediation=f"EC2 → 인스턴스 선택 → 작업 → 보안 → IAM 역할 수정\n→ 적절한 권한의 역할 선택 후 저장"
                        ))
                    else:
                        profile = inst["IamInstanceProfile"].get("Arn", "?")
                        results.append(self._make_result(
                            check_id="EC2-04",
                            name="IAM 역할 미할당",
                            severity=HIGH,
                            resource_id=f"{inst_id} ({name})",
                            status=PASS,
                            detail=f"IAM 역할 할당됨: {profile}"
                        ))
        except Exception as e:
            results.append(self._make_result(
                check_id="EC2-04",
                name="IAM 역할 미할당",
                severity=HIGH,
                resource_id="instances",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeInstances 권한 확인"
            ))
        return results

    # ── EC2-05: User Data 민감 정보 ───────────────────
    def _check_user_data(self, ec2) -> list:
        results = []
        try:
            reservations = ec2.describe_instances().get("Reservations", [])
            instance_ids = [
                inst["InstanceId"]
                for res in reservations
                for inst in res.get("Instances", [])
                if inst.get("State", {}).get("Name") != "terminated"
            ]

            for inst_id in instance_ids:
                try:
                    attr = ec2.describe_instance_attribute(
                        InstanceId=inst_id, Attribute="userData"
                    )
                    value = attr.get("UserData", {}).get("Value")

                    if not value:
                        results.append(self._make_result(
                            check_id="EC2-05",
                            name="User Data 민감 정보",
                            severity=MEDIUM,
                            resource_id=inst_id,
                            status=PASS,
                            detail="User Data 없음"
                        ))
                        continue

                    decoded    = base64.b64decode(value).decode("utf-8", errors="ignore")
                    found      = [kw for kw in SENSITIVE_KEYWORDS if kw in decoded.lower()]
                    snippet    = decoded.strip()[:120].replace("\n", " ") + " ..."

                    if found:
                        results.append(self._make_result(
                            check_id="EC2-05",
                            name="User Data 민감 정보",
                            severity=MEDIUM,
                            resource_id=inst_id,
                            status=FAIL,
                            detail=f"민감 키워드 발견: {', '.join(found)}\n미리보기: {snippet}",
                            remediation="User Data에서 민감 정보 제거:\n"
                                        "EC2 → 인스턴스 중지 → 작업 → 인스턴스 설정 → 사용자 데이터 편집\n"
                                        "→ 비밀번호·키 등 평문 정보 삭제 후 AWS Secrets Manager 또는 Parameter Store 활용"
                        ))
                    else:
                        results.append(self._make_result(
                            check_id="EC2-05",
                            name="User Data 민감 정보",
                            severity=MEDIUM,
                            resource_id=inst_id,
                            status=PASS,
                            detail="민감 키워드 미발견"
                        ))
                except Exception as e:
                    results.append(self._make_result(
                        check_id="EC2-05",
                        name="User Data 민감 정보",
                        severity=MEDIUM,
                        resource_id=inst_id,
                        status=WARN,
                        detail=f"User Data 조회 실패: {e}",
                        remediation="ec2:DescribeInstanceAttribute 권한 확인"
                    ))
        except Exception as e:
            results.append(self._make_result(
                check_id="EC2-05",
                name="User Data 민감 정보",
                severity=MEDIUM,
                resource_id="instances",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeInstances 권한 확인"
            ))
        return results
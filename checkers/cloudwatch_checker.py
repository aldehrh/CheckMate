"""
checkers/cloudwatch_checker.py
Amazon CloudWatch 보안 점검 

점검 항목:
  CW-01  중요 보안 이벤트 지표 필터 및 경보 누락 (루트 계정 사용)
  CW-02  CloudWatch Logs 그룹 KMS 암호화 미적용
  CW-03  로그 그룹 보존 주기 무제한 설정 (Never Expire)
  CW-04  CloudTrail → CloudWatch Logs 연동 누락
  CW-05  VPC Flow Logs 수집 누락
"""

import boto3
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, LOW, PASS, FAIL, WARN

# 탐지할 보안 이벤트 패턴 목록
SECURITY_PATTERNS = [
    ("루트 계정 사용",        '$.userIdentity.type = "Root"'),
    ("IAM 정책 권한 롤백",    "SetDefaultPolicyVersion"),
]


class CloudWatchChecker(BaseChecker):
    SERVICE_NAME = "CloudWatch"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        logs   = boto3.client("logs",       region_name=self.region)
        cw     = boto3.client("cloudwatch", region_name=self.region)
        ct     = boto3.client("cloudtrail", region_name=self.region)
        ec2    = boto3.client("ec2",        region_name=self.region)

        # 로그 그룹 전체 조회
        self._log_group_error = None
        log_groups = self._get_all_log_groups(logs)
        if self._log_group_error:
            report.results.append(self._make_result(
                "CW-00", "로그 그룹 목록 조회", HIGH, "logs",
                WARN, f"조회 실패: {self._log_group_error}", "logs:DescribeLogGroups 권한 확인"
            ))
        elif not log_groups:
            report.results.append(self._make_result(
                "CW-00", "로그 그룹 존재 여부", HIGH, "logs",
                PASS, "생성된 CloudWatch 로그 그룹이 없음"
            ))

        report.results += self._check_security_alarms(logs, cw, log_groups)  # CW-01
        report.results += self._check_kms_encryption(log_groups)              # CW-02
        report.results += self._check_retention_policy(log_groups)            # CW-03
        report.results.append(self._check_cloudtrail_integration(ct))         # CW-04
        report.results += self._check_vpc_flow_logs(ec2)                      # CW-05

        return report

    def _get_all_log_groups(self, logs) -> list:
        groups = []
        try:
            paginator = logs.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                groups += page.get("logGroups", [])
        except Exception as e:
            self._log_group_error = str(e)
        return groups

   # CW-01 ──────────────────────────────────────────
    def _check_security_alarms(self, logs, cw, log_groups) -> list:
        results = []
        for display_name, pattern in SECURITY_PATTERNS:
            found_filter = False
            found_alarm  = False
            try:
                filters = logs.describe_metric_filters(filterNamePrefix="").get("metricFilters", [])
                for f in filters:
                    if pattern.split('"')[1] if '"' in pattern else pattern in f.get("filterPattern", ""):
                        found_filter = True
                        # 연결된 경보 확인
                        for mt in f.get("metricTransformations", []):
                            alarms = cw.describe_alarms_for_metric(
                                MetricName=mt["metricName"],
                                Namespace=mt["metricNamespace"]
                            ).get("MetricAlarms", [])
                            if any(a.get("ActionsEnabled") for a in alarms):
                                found_alarm = True

                if found_filter and found_alarm:
                    results.append(self._make_result(
                        check_id="CW-01",
                        name=f"보안 이벤트 경보: {display_name}",
                        severity=LOW,
                        resource_id="cloudwatch",
                        status=PASS,
                        detail="지표 필터 + 경보 모두 설정됨"
                    ))
                elif found_filter:
                    results.append(self._make_result(
                        check_id="CW-01",
                        name=f"보안 이벤트 경보: {display_name}",
                        severity=LOW,
                        resource_id="cloudwatch",
                        status=WARN,
                        detail="지표 필터는 있으나 활성 경보 없음 — 탐지해도 알림 발송 안 됨",
                        remediation="CloudWatch → 경보 생성 → 해당 지표 선택 → SNS 알림 연동"
                    ))
                else:
                    results.append(self._make_result(
                        check_id="CW-01",
                        name=f"보안 이벤트 경보: {display_name}",
                        severity=LOW,
                        resource_id="cloudwatch",
                        status=FAIL,
                        detail=f"지표 필터 미설정 — '{display_name}' 발생 시 탐지 불가",
                        remediation=f"CloudWatch → 로그 그룹 선택 → 지표 필터 생성\n필터 패턴: {pattern}"
                    ))
            except Exception as e:
                results.append(self._make_result(
                    check_id="CW-01",
                    name=f"보안 이벤트 경보: {display_name}",
                    severity=LOW,
                    resource_id="cloudwatch",
                    status=WARN,
                    detail=f"조회 실패: {e}",
                    remediation="logs:DescribeMetricFilters 권한 확인"
                ))
        return results

    # CW-02 ──────────────────────────────────────────
    def _check_kms_encryption(self, log_groups) -> list:
        results = []
        if not log_groups:
            return results
        for grp in log_groups:
            name    = grp.get("logGroupName", "unknown")
            kms_key = grp.get("kmsKeyId", "")
            results.append(self._make_result(
                check_id="CW-02",
                name="로그 그룹 KMS 암호화",
                severity=LOW,
                resource_id=name,
                status=PASS if kms_key else WARN,
                detail=f"KMS Key: {kms_key}" if kms_key else "KMS 암호화 미적용 — 읽기 권한 탈취 시 민감 데이터 노출",
                remediation=f"aws logs associate-kms-key --log-group-name {name} --kms-key-id <KMS-KEY-ARN>" if not kms_key else "조치 불필요"
            ))
        return results

    # CW-03 ──────────────────────────────────────────
    def _check_retention_policy(self, log_groups) -> list:
        results = []
        if not log_groups:
            return results
        for grp in log_groups:
            name      = grp.get("logGroupName", "unknown")
            retention = grp.get("retentionInDays")
            if not retention:
                results.append(self._make_result(
                    check_id="CW-03",
                    name="로그 그룹 보존 주기 무제한",
                    severity=LOW,
                    resource_id=name,
                    status=WARN,
                    detail="보존 주기 미설정 (Never Expire) — 스토리지 비용 무제한 증가",
                    remediation=f"aws logs put-retention-policy --log-group-name {name} --retention-in-days 365"
                ))
            else:
                results.append(self._make_result(
                    check_id="CW-03",
                    name="로그 그룹 보존 주기 무제한",
                    severity=LOW,
                    resource_id=name,
                    status=PASS,
                    detail=f"보존 주기: {retention}일"
                ))
        return results

    # CW-04 ──────────────────────────────────────────
    def _check_cloudtrail_integration(self, ct):
        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            if not trails:
                return self._make_result(
                    check_id="CW-04",
                    name="CloudTrail → CloudWatch 연동",
                    severity=LOW,
                    resource_id="cloudtrail",
                    status=FAIL,
                    detail="Trail 없음 — API 활동 실시간 모니터링 불가",
                    remediation="CloudTrail 콘솔 → 추적 생성 → CloudWatch Logs 연동 활성화"
                )
            linked = [t for t in trails if t.get("CloudWatchLogsLogGroupArn")]
            if linked:
                return self._make_result(
                    check_id="CW-04",
                    name="CloudTrail → CloudWatch 연동",
                    severity=LOW,
                    resource_id="cloudtrail",
                    status=PASS,
                    detail=f"{len(linked)}/{len(trails)}개 Trail이 CloudWatch Logs와 연동됨"
                )
            return self._make_result(
                check_id="CW-04",
                name="CloudTrail → CloudWatch 연동",
                severity=LOW,
                resource_id="cloudtrail",
                status=FAIL,
                detail="모든 Trail이 CloudWatch Logs 미연동 — 실시간 보안 탐지 불가",
                remediation="CloudTrail → 추적 선택 → CloudWatch Logs 편집 → 활성화"
            )
        except Exception as e:
            return self._make_result(
                check_id="CW-04",
                name="CloudTrail → CloudWatch 연동",
                severity=LOW,
                resource_id="cloudtrail",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="cloudtrail:DescribeTrails 권한 확인"
            )

    # CW-05 ──────────────────────────────────────────
    def _check_vpc_flow_logs(self, ec2) -> list:
        results = []
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            if not vpcs:
                return results

            flow_logs   = ec2.describe_flow_logs().get("FlowLogs", [])
            active_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                is_default = vpc.get("IsDefault", False)
                if vpc_id in active_vpcs:
                    results.append(self._make_result(
                        check_id="CW-05",
                        name="VPC Flow Logs 수집",
                        severity=LOW,
                        resource_id=vpc_id,
                        status=PASS,
                        detail="Flow Logs ACTIVE — 네트워크 트래픽 기록 중"
                    ))
                else:
                    results.append(self._make_result(
                        check_id="CW-05",
                        name="VPC Flow Logs 수집",
                        severity=LOW,
                        resource_id=vpc_id,
                        status=WARN if is_default else FAIL,
                        detail="Flow Logs 미설정 — 내부 횡적 이동·데이터 유출 탐지 불가",
                        remediation=f"VPC 콘솔 → {vpc_id} → 플로우 로그 탭 → 플로우 로그 생성\n(필터: 전체, 대상: CloudWatch Logs)"
                    ))
        except Exception as e:
            results.append(self._make_result(
                check_id="CW-05",
                name="VPC Flow Logs 수집",
                severity=LOW,
                resource_id="vpc",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="ec2:DescribeFlowLogs 권한 확인"
            ))
        return results
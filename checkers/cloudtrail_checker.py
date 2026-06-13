"""
checkers/cloudtrail_checker.py
AWS CloudTrail 보안 점검 

점검 항목:
  CT-01  조직(Organizations) 추적 미설정 (IsOrganizationTrail)
  CT-02  S3 Object Lock(WORM) 미설정
  CT-03  데이터 이벤트 추적 누락 (AdvancedEventSelectors)
  CT-04  실시간 경고 체계 미설정 (CloudWatch Logs 연동)
  CT-05  단일 리전 설정 (IsMultiRegionTrail)
"""

import boto3
from botocore.exceptions import ClientError
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, LOW, PASS, FAIL, WARN


class CloudTrailChecker(BaseChecker):
    SERVICE_NAME = "CloudTrail"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        ct     = boto3.client("cloudtrail", region_name=self.region)
        s3     = boto3.client("s3", region_name=self.region)

        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        except Exception as e:
            report.results.append(self._make_result(
                "CT-00", "CloudTrail 조회", HIGH, "cloudtrail",
                WARN, f"트레일 조회 실패: {e}", "cloudtrail:DescribeTrails 권한 확인"
            ))
            return report

        if not trails:
            report.results.append(self._make_result(
                "CT-00", "CloudTrail 활성화", HIGH, "cloudtrail",
                FAIL, "생성된 Trail이 없음 — AWS API 활동이 전혀 기록되지 않음",
                "CloudTrail 콘솔 → 추적 생성 → 모든 리전 적용 + CloudWatch Logs 연동"
            ))
            return report

        for trail in trails:
            name = trail.get("Name", "unknown")
            report.results.append(self._check_org_trail(trail))
            report.results.append(self._check_s3_object_lock(trail, s3))
            report.results.append(self._check_data_events(trail, ct))
            report.results.append(self._check_cloudwatch_integration(trail))
            report.results.append(self._check_multi_region(trail))

        return report

    # CT-01 ──────────────────────────────────────────
    def _check_org_trail(self, trail):
        name   = trail.get("Name", "unknown")
        is_org = trail.get("IsOrganizationTrail", False)
        
        detail = f"IsOrganizationTrail={is_org}" + (" — 하위 계정 이벤트 통합 수집 중" if is_org else " — 하위 계정 이벤트 누락 가능")
        
        return self._make_result(
            check_id="CT-01",
            name="조직 추적(Organization Trail) 미설정",
            severity=LOW,
            resource_id=name,
            status=PASS if is_org else WARN,
            detail=detail,
            remediation="CloudTrail → 추적 선택 → 편집 → '조직의 모든 계정에 대해 활성화' 체크" if not is_org else "조치 불필요"
        )

    # CT-02 ──────────────────────────────────────────
    def _check_s3_object_lock(self, trail, s3):
        name       = trail.get("Name", "unknown")
        bucket     = trail.get("S3BucketName", "")
        if not bucket:
            return self._make_result(
                check_id="CT-02",
                name="S3 Object Lock(WORM) 미설정",
                severity=LOW,
                resource_id=name,
                status=WARN,
                detail="연결된 S3 버킷 정보 없음",
                remediation="Trail에 S3 버킷 연결 확인"
            )
        try:
            resp = s3.get_object_lock_configuration(Bucket=bucket)
            cfg  = resp.get("ObjectLockConfiguration", {})
            enabled = cfg.get("ObjectLockEnabled") == "Enabled"
            rule    = cfg.get("Rule", {})
            mode    = rule.get("DefaultRetention", {}).get("Mode", "미설정")
            
            return self._make_result(
                check_id="CT-02",
                name="S3 Object Lock(WORM) 미설정",
                severity=LOW,
                resource_id=f"{name} → s3://{bucket}",
                status=PASS if enabled else WARN,
                detail=f"ObjectLockEnabled={enabled}, Mode={mode}",
                remediation=f"S3 → {bucket} → 속성 → 객체 잠금 → 기본 보존 활성화 (거버넌스/규정준수)" if not enabled else "조치 불필요"
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code != "ObjectLockConfigurationNotFoundError":
                return self._make_result(
                    check_id="CT-02",
                    name="S3 Object Lock(WORM) 미설정",
                    severity=LOW,
                    resource_id=f"{name} → s3://{bucket}",
                    status=WARN,
                    detail=f"조회 실패: {code}",
                    remediation="s3:GetObjectLockConfiguration 권한 확인"
                )
            return self._make_result(
                check_id="CT-02",
                name="S3 Object Lock(WORM) 미설정",
                severity=LOW,
                resource_id=f"{name} → s3://{bucket}",
                status=WARN,
                detail="Object Lock 설정 없음 — 관리자 권한 탈취 시 로그 영구 삭제 가능",
                remediation="버킷 생성 시에만 Object Lock 활성화 가능. 신규 버킷에 적용 후 Trail 재연결 권장"
            )
        except Exception as e:
            return self._make_result(
                check_id="CT-02",
                name="S3 Object Lock(WORM) 미설정",
                severity=LOW,
                resource_id=f"{name} → s3://{bucket}",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="s3:GetObjectLockConfiguration 권한 확인"
            )

    # CT-03 ──────────────────────────────────────────
    def _check_data_events(self, trail, ct):
        name = trail.get("Name", "unknown")
        try:
            resp      = ct.get_event_selectors(TrailName=name)
            advanced  = resp.get("AdvancedEventSelectors", [])
            basic     = resp.get("EventSelectors", [])

            # AdvancedEventSelectors에서 데이터 이벤트 확인
            has_data = False
            if advanced:
                for sel in advanced:
                    for fld in sel.get("FieldSelectors", []):
                        if fld.get("Field") == "eventCategory" and "Data" in fld.get("Equals", []):
                            has_data = True
            elif basic:
                for sel in basic:
                    if sel.get("DataResources"):
                        has_data = True

            detail = "데이터 이벤트 추적 활성화됨" if has_data else "데이터 이벤트 미설정 — S3 객체 접근·Lambda 호출 이력 누락"

            return self._make_result(
                check_id="CT-03",
                name="데이터 이벤트 추적 누락",
                severity=LOW,
                resource_id=name,
                status=PASS if has_data else WARN,
                detail=detail,
                remediation="CloudTrail → 추적 선택 → 데이터 이벤트 편집 → S3/Lambda 데이터 이벤트 활성화" if not has_data else "조치 불필요"
            )
        except Exception as e:
            return self._make_result(
                check_id="CT-03",
                name="데이터 이벤트 추적 누락",
                severity=LOW,
                resource_id=name,
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="cloudtrail:GetEventSelectors 권한 확인"
            )

    # CT-04 ──────────────────────────────────────────
    def _check_cloudwatch_integration(self, trail):
        name    = trail.get("Name", "unknown")
        log_arn = trail.get("CloudWatchLogsLogGroupArn", "")
        if log_arn:
            return self._make_result(
                check_id="CT-04",
                name="실시간 경고 체계 미설정",
                severity=LOW,
                resource_id=name,
                status=PASS,
                detail=f"CloudWatch Logs 연동됨: {log_arn}",
                remediation="조치 불필요"
            )
        return self._make_result(
            check_id="CT-04",
            name="실시간 경고 체계 미설정",
            severity=LOW,
            resource_id=name,
            status=FAIL,
            detail="CloudWatchLogsLogGroupArn 없음 — S3 저장만 되어 실시간 탐지 불가",
            remediation="CloudTrail → 추적 선택 → CloudWatch Logs 편집 → 활성화 + 로그 그룹·IAM 역할 지정"
        )

    # CT-05 ──────────────────────────────────────────
    def _check_multi_region(self, trail):
        name       = trail.get("Name", "unknown")
        is_multi   = trail.get("IsMultiRegionTrail", False)
        
        detail = f"IsMultiRegionTrail={is_multi}" + (" — 전체 리전 API 활동 수집 중" if is_multi else " — 미사용 리전에서의 침입 활동 탐지 불가")
        
        return self._make_result(
            check_id="CT-05",
            name="단일 리전 설정",
            severity=LOW,
            resource_id=name,
            status=PASS if is_multi else WARN,
            detail=detail,
            remediation="CloudTrail → 추적 선택 → 편집 → '모든 리전에 추적 적용' 체크" if not is_multi else "조치 불필요"
        )
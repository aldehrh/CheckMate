"""
checkers/iam_checker.py
Amazon IAM 보안 점검 

점검 항목:
  IAM-01  루트 계정 일상적 사용 여부
  IAM-02  액세스 키 90일 이상 방치
  IAM-03  사용자 MFA 미설정
  IAM-04  와일드카드(*) 과도한 권한 부여
  IAM-05  사용자에게 직접 정책 연결
"""

import csv, io, boto3
from datetime import datetime, timezone, timedelta
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, LOW, PASS, FAIL, WARN


class IAMChecker(BaseChecker):
    SERVICE_NAME   = "IAM"
    STALE_KEY_DAYS = 90

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        iam    = boto3.client("iam", region_name=self.region)

        report.results.append(self._check_root_usage(iam))

        try:
            users = [u for page in iam.get_paginator("list_users").paginate() for u in page["Users"]]
        except Exception as e:
            report.results.append(self._make_result(
                "IAM-00", "IAM 사용자 목록 조회", HIGH, "iam",
                WARN, f"조회 실패: {e}", "iam:ListUsers 권한 확인"
            ))
            users = []

        if not users:
            report.results.append(self._make_result(
                "IAM-00", "IAM 사용자 존재 여부", HIGH, "iam",
                PASS, "조회된 IAM 사용자가 없음 (루트 계정만 존재하거나 list_users 결과 0건)"
            ))

        for user in users:
            uname = user["UserName"]
            report.results += self._check_access_keys(iam, uname)
            report.results.append(self._check_mfa(iam, uname))
            report.results += self._check_wildcard_policies(iam, uname)
            report.results.append(self._check_direct_policy(iam, uname))

        return report

    # IAM-01 ─────────────────────────────────────────
    def _check_root_usage(self, iam):
        try:
            while iam.generate_credential_report().get("State") != "COMPLETE":
                pass
            content = iam.get_credential_report()["Content"].decode("utf-8")
            root    = next((r for r in csv.DictReader(io.StringIO(content))
                            if r["user"] == "<root_account>"), None)
            if not root:
                return self._make_result(
                    check_id="IAM-01",
                    name="루트 계정 일상적 사용",
                    severity=MEDIUM,
                    resource_id="root",
                    status=WARN,
                    detail="루트 계정 정보를 찾을 수 없음",
                    remediation="credential report 권한 확인 필요"
                )

            now, recent = datetime.now(timezone.utc), []
            for f in ["password_last_used","access_key_1_last_used_date","access_key_2_last_used_date"]:
                v = root.get(f,"")
                if v and v not in ("N/A","not_supported","no_information",""):
                    try:
                        days = (now - datetime.fromisoformat(v.replace("Z","+00:00"))).days
                        if days <= 90: recent.append(f"{f}: {days}일 전")
                    except ValueError: pass

            if recent:
                return self._make_result(
                    check_id="IAM-01",
                    name="루트 계정 일상적 사용",
                    severity=MEDIUM,
                    resource_id="root",
                    status=FAIL,
                    detail="루트 계정 최근 사용 감지: "+", ".join(recent),
                    remediation="IAM 관리자 계정 생성 후 루트 계정 봉인 권장 (MFA 설정 필수)"
                )
            return self._make_result(
                check_id="IAM-01",
                name="루트 계정 일상적 사용",
                severity=MEDIUM,
                resource_id="root",
                status=PASS,
                detail="최근 90일 내 루트 계정 사용 기록 없음"
            )
        except Exception as e:
            return self._make_result(
                check_id="IAM-01",
                name="루트 계정 일상적 사용",
                severity=MEDIUM,
                resource_id="root",
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="iam:GenerateCredentialReport 권한 확인"
            )

    # IAM-02 ─────────────────────────────────────────
    def _check_access_keys(self, iam, username) -> list:
        results = []
        try:
            now  = datetime.now(timezone.utc)
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                kid  = key["AccessKeyId"]
                days = (now - key["CreateDate"]).days
                rid  = f"{username}/{kid[:8]}..."
                if key["Status"] == "Inactive":
                    results.append(self._make_result(
                        check_id="IAM-02",
                        name="비활성 액세스 키 방치",
                        severity=HIGH,
                        resource_id=rid,
                        status=WARN,
                        detail=f"비활성 키 존재 (생성 {days}일 전) — 미사용 시 삭제 권장",
                        remediation=f"aws iam delete-access-key --user-name {username} --access-key-id {kid}"
                    ))
                elif days > self.STALE_KEY_DAYS:
                    results.append(self._make_result(
                        check_id="IAM-02",
                        name="액세스 키 장기 미교체",
                        severity=HIGH,
                        resource_id=rid,
                        status=FAIL,
                        detail=f"활성 키 {days}일째 미교체 (90일 초과) — 코드 내 하드코딩 위험",
                        remediation=f"새 키 발급 후 기존 키 삭제 (aws iam create-access-key / delete-access-key)"
                    ))
                else:
                    results.append(self._make_result(
                        check_id="IAM-02",
                        name="액세스 키 장기 미교체",
                        severity=HIGH,
                        resource_id=rid,
                        status=PASS,
                        detail=f"활성 키 생성 {days}일 경과 (90일 이내)"
                    ))
        except Exception as e:
            results.append(self._make_result(
                check_id="IAM-02",
                name="액세스 키 장기 미교체",
                severity=HIGH,
                resource_id=username,
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="iam:ListAccessKeys 권한 확인"
            ))
        return results

    # IAM-03 ─────────────────────────────────────────
    def _check_mfa(self, iam, username):
        try:
            devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not devices:
                return self._make_result(
                    check_id="IAM-03",
                    name="사용자 MFA 미설정",
                    severity=MEDIUM,
                    resource_id=username,
                    status=FAIL,
                    detail="MFA 미등록 — 비밀번호 유출 시 방어 수단 없음",
                    remediation="AWS 콘솔 → IAM → 사용자 → 보안 자격 증명 → MFA 디바이스 할당"
                )
            return self._make_result(
                check_id="IAM-03",
                name="사용자 MFA 미설정",
                severity=MEDIUM,
                resource_id=username,
                status=PASS,
                detail=f"MFA 기기 {len(devices)}개 등록됨"
            )
        except Exception as e:
            return self._make_result(
                check_id="IAM-03",
                name="사용자 MFA 미설정",
                severity=MEDIUM,
                resource_id=username,
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="iam:ListMFADevices 권한 확인"
            )

    # IAM-04 ─────────────────────────────────────────
    def _check_wildcard_policies(self, iam, username) -> list:
        results = []
        try:
            for policy in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies",[]):
                pname, parn = policy["PolicyName"], policy["PolicyArn"]
                try:
                    vid  = iam.get_policy(PolicyArn=parn)["Policy"]["DefaultVersionId"]
                    doc  = iam.get_policy_version(PolicyArn=parn,VersionId=vid)["PolicyVersion"]["Document"]
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict): stmts = [stmts]
                    vulns = []
                    for i, s in enumerate(stmts):
                        if s.get("Effect") != "Allow": continue
                        a, r = s.get("Action",""), s.get("Resource","")
                        wa = a=="*" or (isinstance(a,list) and "*" in a)
                        wr = r=="*" or (isinstance(r,list) and "*" in r)
                        if wa or wr:
                            vulns.append(f"[{i}]:"+("Action=* " if wa else "")+("Resource=*" if wr else ""))
                    if vulns:
                        results.append(self._make_result(
                            check_id="IAM-04",
                            name="와일드카드(*) 과도한 권한",
                            severity=HIGH,
                            resource_id=f"{username}/{pname}",
                            status=FAIL,
                            detail="와일드카드 남용: "+" ".join(vulns),
                            remediation="정책 편집 → 필요한 Action/Resource만 명시 (예: s3:GetObject, arn:aws:s3:::bucket/*)"
                        ))
                    else:
                        results.append(self._make_result(
                            check_id="IAM-04",
                            name="와일드카드(*) 과도한 권한",
                            severity=HIGH,
                            resource_id=f"{username}/{pname}",
                            status=PASS,
                            detail="와일드카드 남용 없음"
                        ))
                except Exception:
                    pass
        except Exception as e:
            results.append(self._make_result(
                check_id="IAM-04",
                name="와일드카드(*) 과도한 권한",
                severity=HIGH,
                resource_id=username,
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="iam:ListAttachedUserPolicies 권한 확인"
            ))
        return results

    # IAM-05 ─────────────────────────────────────────
    def _check_direct_policy(self, iam, username):
        try:
            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies",[])
            inline   = iam.list_user_policies(UserName=username).get("PolicyNames",[])
            issues   = []
            if attached: issues.append(f"관리형 정책 직접 연결 {len(attached)}개: "+", ".join(p["PolicyName"] for p in attached))
            if inline:   issues.append(f"인라인 정책 직접 내장 {len(inline)}개: "+", ".join(inline))
            if issues:
                return self._make_result(
                    check_id="IAM-05",
                    name="사용자 직접 정책 연결",
                    severity=LOW,
                    resource_id=username,
                    status=WARN,
                    detail="; ".join(issues),
                    remediation="IAM 그룹 생성 → 그룹에 정책 부여 → 사용자를 그룹에 추가 후 직접 연결 정책 제거"
                )
            return self._make_result(
                check_id="IAM-05",
                name="사용자 직접 정책 연결",
                severity=LOW,
                resource_id=username,
                status=PASS,
                detail="직접 연결 정책 없음"
            )
        except Exception as e:
            return self._make_result(
                check_id="IAM-05",
                name="사용자 직접 정책 연결",
                severity=LOW,
                resource_id=username,
                status=WARN,
                detail=f"조회 실패: {e}",
                remediation="iam:ListUserPolicies 권한 확인"
            )
"""
checkers/s3_checker.py
Amazon S3 보안 점검 — 담당: 김재현 (2022243109)

점검 항목 (자료조사 기준):
  S3-01  버킷 퍼블릭 접근 차단 설정 (Block Public Access 4개 항목)
  S3-02  버킷 정책 퍼블릭 허용 여부 (Principal=*)
  S3-03  서버 측 암호화(SSE) 미적용
  S3-04  버전 관리 비활성화
  S3-05  서버 액세스 로깅 미설정
  S3-06  ACL 퍼블릭 허용 여부
"""

import json, boto3
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, PASS, FAIL, WARN


class S3Checker(BaseChecker):
    SERVICE_NAME = "S3"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        s3     = boto3.client("s3", region_name=self.region)

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception:
            return report

        for b in buckets:
            name = b["Name"]
            report.results.append(self._check_public_access_block(s3, name))  # S3-01
            report.results.append(self._check_bucket_policy(s3, name))        # S3-02
            report.results.append(self._check_encryption(s3, name))           # S3-03
            report.results.append(self._check_versioning(s3, name))           # S3-04
            report.results.append(self._check_logging(s3, name))              # S3-05
            report.results.append(self._check_acl(s3, name))                  # S3-06

        return report

    # S3-01 ──────────────────────────────────────────
    def _check_public_access_block(self, s3, name):
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            bpa = cfg.get("BlockPublicAcls", False)
            ipa = cfg.get("IgnorePublicAcls", False)
            bpp = cfg.get("BlockPublicPolicy", False)
            rpb = cfg.get("RestrictPublicBuckets", False)
            all_ok = bpa and ipa and bpp and rpb

            detail = (
                "4개 항목 모두 True" if all_ok
                else f"BlockPublicAcls={bpa}, IgnorePublicAcls={ipa}, "
                     f"BlockPublicPolicy={bpp}, RestrictPublicBuckets={rpb}"
            )
            return self._make_result("S3-01","퍼블릭 액세스 차단 설정",HIGH,name,
                PASS if all_ok else FAIL, detail,
                f"aws s3api put-public-access-block --bucket {name} "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                if not all_ok else "조치 불필요")
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            return self._make_result("S3-01","퍼블릭 액세스 차단 설정",HIGH,name,
                FAIL,"퍼블릭 액세스 차단 설정 자체가 없음 (모든 옵션 꺼진 상태)",
                f"aws s3api put-public-access-block --bucket {name} "
                "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true")
        except Exception as e:
            return self._make_result("S3-01","퍼블릭 액세스 차단 설정",HIGH,name,
                WARN,f"조회 실패: {e}","s3:GetBucketPublicAccessBlock 권한 확인")

    # S3-02 ──────────────────────────────────────────
    def _check_bucket_policy(self, s3, name):
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            vulns  = []
            for i, stmt in enumerate(policy.get("Statement", [])):
                if stmt.get("Effect") != "Allow": continue
                principal = stmt.get("Principal", "")
                action    = stmt.get("Action", "")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    vulns.append(f"규칙{i+1}: Principal=* (누구나 접근 허용)")
                if action == "*" or (isinstance(action, list) and "*" in action):
                    vulns.append(f"규칙{i+1}: Action=* (모든 작업 허용)")
            if vulns:
                return self._make_result("S3-02","버킷 정책 퍼블릭 허용",HIGH,name,
                    FAIL,"; ".join(vulns),
                    f"aws s3api get-bucket-policy --bucket {name}  # 정책 확인 후 Principal=* 규칙 제거")
            return self._make_result("S3-02","버킷 정책 퍼블릭 허용",HIGH,name,
                PASS,"퍼블릭 허용 정책 없음")
        except s3.exceptions.NoSuchBucketPolicy:
            return self._make_result("S3-02","버킷 정책 퍼블릭 허용",HIGH,name,
                PASS,"버킷 정책 없음 (기본 차단 상태)")
        except Exception as e:
            return self._make_result("S3-02","버킷 정책 퍼블릭 허용",HIGH,name,
                WARN,f"조회 실패: {e}","s3:GetBucketPolicy 권한 확인")

    # S3-03 ──────────────────────────────────────────
    def _check_encryption(self, s3, name):
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            algo  = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            kms   = rules[0]["ApplyServerSideEncryptionByDefault"].get("KMSMasterKeyID","Default")
            detail = f"암호화 알고리즘: {algo}" + (f", KMS Key: {kms}" if algo == "aws:kms" else "")
            return self._make_result("S3-03","서버 측 암호화(SSE) 설정",HIGH,name,PASS,detail)
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            return self._make_result("S3-03","서버 측 암호화(SSE) 설정",HIGH,name,
                FAIL,"SSE 미설정 — 데이터 평문 저장 위험",
                f"aws s3api put-bucket-encryption --bucket {name} "
                "--server-side-encryption-configuration "
                "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'")
        except Exception as e:
            return self._make_result("S3-03","서버 측 암호화(SSE) 설정",HIGH,name,
                WARN,f"조회 실패: {e}","s3:GetEncryptionConfiguration 권한 확인")

    # S3-04 ──────────────────────────────────────────
    def _check_versioning(self, s3, name):
        try:
            resp   = s3.get_bucket_versioning(Bucket=name)
            status = resp.get("Status","Disabled")
            mfa    = resp.get("MFADelete","Disabled")
            if status == "Enabled":
                return self._make_result("S3-04","버전 관리 설정",MEDIUM,name,
                    PASS,f"버전 관리 활성화 (MFA Delete: {mfa})")
            return self._make_result("S3-04","버전 관리 설정",MEDIUM,name,
                WARN,f"버전 관리 {status} — 랜섬웨어·실수 삭제 시 복구 불가",
                f"aws s3api put-bucket-versioning --bucket {name} "
                "--versioning-configuration Status=Enabled")
        except Exception as e:
            return self._make_result("S3-04","버전 관리 설정",MEDIUM,name,
                WARN,f"조회 실패: {e}","s3:GetBucketVersioning 권한 확인")

    # S3-05 ──────────────────────────────────────────
    def _check_logging(self, s3, name):
        try:
            resp = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" in resp:
                target = resp["LoggingEnabled"].get("TargetBucket","?")
                prefix = resp["LoggingEnabled"].get("TargetPrefix","없음")
                return self._make_result("S3-04","서버 액세스 로깅",MEDIUM,name,
                    PASS,f"로깅 활성화 → 저장 버킷: {target}, 폴더: {prefix}")
            return self._make_result("S3-05","서버 액세스 로깅",MEDIUM,name,
                WARN,"로깅 비활성화 — 침해 사고 시 접근 기록 추적 불가",
                f"로그 저장용 별도 버킷 생성 후:\n"
                f"aws s3api put-bucket-logging --bucket {name} "
                "--bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\","
                f"\"TargetPrefix\":\"{name}/\"}}'")
        except Exception as e:
            return self._make_result("S3-05","서버 액세스 로깅",MEDIUM,name,
                WARN,f"조회 실패: {e}","s3:GetBucketLogging 권한 확인")

    # S3-06 ──────────────────────────────────────────
    def _check_acl(self, s3, name):
        try:
            grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
            ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
            AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            vulns = []
            for g in grants:
                uri  = g.get("Grantee", {}).get("URI", "")
                perm = g.get("Permission", "")
                if uri == ALL_USERS:
                    vulns.append(f"모든 외부 사용자에게 '{perm}' 허용")
                elif uri == AUTH_USERS:
                    vulns.append(f"인증된 모든 AWS 계정에게 '{perm}' 허용")
            if vulns:
                return self._make_result("S3-06","ACL 퍼블릭 허용",HIGH,name,
                    FAIL,"; ".join(vulns),
                    f"aws s3api put-bucket-acl --bucket {name} --acl private")
            return self._make_result("S3-06","ACL 퍼블릭 허용",HIGH,name,
                PASS,"외부 접근 ACL 없음")
        except Exception as e:
            return self._make_result("S3-06","ACL 퍼블릭 허용",HIGH,name,
                WARN,f"조회 실패: {e}","s3:GetBucketAcl 권한 확인")

"""
checkers/base.py
모든 서비스 체커가 공유하는 공통 데이터 클래스 및 베이스 체커
"""

from dataclasses import dataclass, field
from typing import Optional


# ── 위험도 상수 ──────────────────────────────────────
HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"

# ── 상태 상수 ────────────────────────────────────────
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


@dataclass
class CheckResult:
    """개별 점검 항목 결과 — 모든 체커가 이 형식으로 반환"""
    service:     str        # "RDS" | "S3" | "IAM" | "EC2"
    check_id:    str        # 예: "RDS-01", "S3-03"
    name:        str        # 점검 항목명
    severity:    str        # HIGH | MEDIUM | LOW
    status:      str        # PASS | FAIL | WARN
    resource_id: str        # 점검 대상 리소스 식별자
    detail:      str        # 현재 상태 설명
    remediation: str        # 조치 방법 (PASS면 "조치 불필요")


@dataclass
class ServiceReport:
    """서비스별 점검 결과 묶음"""
    service:  str
    results:  list[CheckResult] = field(default_factory=list)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for r in self.results if r.status == WARN)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.status == PASS)

    @property
    def score(self) -> int:
        """100점 만점 보안 점수 (FAIL=-10, WARN=-5)"""
        total = len(self.results)
        if total == 0:
            return 100
        deduction = self.fail_count * 10 + self.warn_count * 5
        return max(0, 100 - deduction)


class BaseChecker:
    """모든 서비스 체커가 상속받는 기반 클래스"""
    SERVICE_NAME: str = ""

    def __init__(self, region: str = "ap-northeast-2"):
        self.region = region

    def run(self) -> ServiceReport:
        """각 팀원이 오버라이드해서 구현. ServiceReport를 반환해야 함."""
        raise NotImplementedError(f"{self.__class__.__name__}.run() 미구현")

    def _make_result(
        self,
        check_id:    str,
        name:        str,
        severity:    str,
        status:      str,
        resource_id: str,
        detail:      str,
        remediation: str = "조치 불필요",
    ) -> CheckResult:
        """CheckResult 생성 헬퍼"""
        return CheckResult(
            service=self.SERVICE_NAME,
            check_id=check_id,
            name=name,
            severity=severity,
            status=status,
            resource_id=resource_id,
            detail=detail,
            remediation=remediation,
        )

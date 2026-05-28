# AWS 보안 점검 도구

> RDS · S3 · IAM · EC2 보안 설정을 자동 점검하고 HTML 보고서를 생성합니다.

## 프로젝트 구조

```
aws_security_checker/
├── main.py                  # 진입점 — 실행 및 통합 보고서
├── requirements.txt
├── checkers/
│   ├── __init__.py
│   ├── base.py              # 공통 클래스 (CheckResult, BaseChecker)
│   ├── rds_checker.py       # Amazon RDS 점검 (박민서)
│   ├── s3_checker.py        # Amazon S3 점검
│   ├── iam_checker.py       # Amazon IAM 점검
│   └── ec2_checker.py       # Amazon EC2 점검
└── report/
    ├── __init__.py
    └── html_report.py       # HTML 보고서 생성기
```

## 점검 항목

| 서비스 | ID | 항목 | 위험도 |
|--------|-----|------|--------|
| RDS | RDS-01 | 퍼블릭 접근 허용 | HIGH |
| RDS | RDS-02 | 기본/약한 마스터 계정명 | HIGH |
| RDS | RDS-03 | 저장 데이터 암호화 미적용 | HIGH |
| RDS | RDS-04 | 보안 그룹 과다 개방 | HIGH |
| RDS | RDS-05 | 자동 백업 보존 기간 | MEDIUM |
| RDS | RDS-06 | SSL/TLS 전송 암호화 | MEDIUM |
| RDS | RDS-07 | CloudWatch 로그 설정 | MEDIUM |
| S3 | S3-01 | 퍼블릭 액세스 차단 | HIGH |
| S3 | S3-02 | 버킷 ACL 퍼블릭 허용 | HIGH |
| S3 | S3-03 | 버킷 암호화(SSE) | HIGH |
| S3 | S3-04 | 버전 관리 설정 | MEDIUM |
| S3 | S3-05 | 서버 액세스 로깅 | MEDIUM |
| S3 | S3-06 | 버킷 정책 퍼블릭 허용 | HIGH |
| IAM | IAM-01 | 루트 계정 MFA | HIGH |
| IAM | IAM-02 | 루트 계정 액세스 키 | HIGH |
| IAM | IAM-03 | 사용자 MFA 미설정 | HIGH |
| IAM | IAM-04 | 90일+ 미사용 액세스 키 | MEDIUM |
| IAM | IAM-05 | AdministratorAccess 직접 연결 | HIGH |
| IAM | IAM-06 | 비밀번호 정책 | MEDIUM |
| EC2 | EC2-01 | 보안 그룹 SSH(22) 개방 | HIGH |
| EC2 | EC2-02 | 보안 그룹 RDP(3389) 개방 | HIGH |
| EC2 | EC2-03 | 보안 그룹 전체 포트 개방 | HIGH |
| EC2 | EC2-04 | EBS 볼륨 암호화 미적용 | HIGH |
| EC2 | EC2-05 | 퍼블릭 IP 자동 할당 서브넷 | MEDIUM |
| EC2 | EC2-06 | IMDSv2 미강제 | MEDIUM |

## 설치 및 실행

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. AWS credentials 설정 (아래 중 하나)
aws configure                          # CLI 설정
export AWS_ACCESS_KEY_ID=...           # 환경변수
export AWS_SECRET_ACCESS_KEY=...

# 3. 전체 서비스 점검 (서울 리전)
python main.py

# 4. 특정 서비스만 점검
python main.py --services RDS S3

# 5. 리전·출력파일 지정
python main.py --region us-east-1 --output report.html
```

## 필요 IAM 권한

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "rds:Describe*",
      "s3:GetBucket*", "s3:ListAllMyBuckets",
      "iam:Get*", "iam:List*",
      "ec2:Describe*"
    ],
    "Resource": "*"
  }]
}
```

## 새 체커 추가 방법 (팀원 가이드)

```python
# checkers/lambda_checker.py
from .base import BaseChecker, ServiceReport

class LambdaChecker(BaseChecker):
    SERVICE_NAME = "Lambda"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        # ... 점검 로직
        report.results.append(self._make_result(...))
        return report
```

그 다음 `checkers/__init__.py`의 `ALL_CHECKERS`에 추가하면 끝.

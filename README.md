# AWS 보안 점검 도구

> RDS · S3 · IAM · EC2 · CloudTrail · CloudWatch · VPC 보안 설정을 자동 점검하고 웹 대시보드로 결과를 보여줍니다.

## 프로젝트 구조

```
aws_security_checker/
├── main.py                        # 진입점 — 점검 실행 + 웹 서버 시작
├── requirements.txt
├── checkers/
│   ├── __init__.py
│   ├── base.py                    # 공통 클래스 (CheckResult, BaseChecker)
│   ├── rds_checker.py             # Amazon RDS 점검       
│   ├── s3_checker.py              # Amazon S3 점검         
│   ├── iam_checker.py             # Amazon IAM 점검        
│   ├── ec2_checker.py             # Amazon EC2 점검        
│   ├── cloudtrail_checker.py      # AWS CloudTrail 점검    
│   ├── cloudwatch_checker.py      # Amazon CloudWatch 점검 
│   └── vpc_checker.py             # Amazon VPC 점검       
└── report/
    ├── __init__.py
    └── web_server.py              # Flask 웹 대시보드
```

## 점검 항목 (총 37개)

| 서비스 | ID | 항목 | 위험도 |
|--------|-----|------|--------|
| RDS | RDS-01 | 퍼블릭 접근 허용 | HIGH |
| RDS | RDS-02 | 기본/약한 마스터 계정명 | HIGH |
| RDS | RDS-03 | 저장 데이터 암호화 미적용 | HIGH |
| RDS | RDS-04 | 보안 그룹 과다 개방 | HIGH |
| RDS | RDS-05 | 자동 백업 보존 기간 | MEDIUM |
| RDS | RDS-06 | SSL/TLS 전송 암호화 | MEDIUM |
| RDS | RDS-07 | CloudWatch 로그 설정 | MEDIUM |
| S3 | S3-01 | 퍼블릭 액세스 차단 설정 | HIGH |
| S3 | S3-02 | 버킷 정책 퍼블릭 허용 | HIGH |
| S3 | S3-03 | 서버 측 암호화(SSE) 미적용 | HIGH |
| S3 | S3-04 | 버전 관리 비활성화 | MEDIUM |
| S3 | S3-05 | 서버 액세스 로깅 미설정 | MEDIUM |
| S3 | S3-06 | ACL 퍼블릭 허용 | HIGH |
| IAM | IAM-01 | 루트 계정 일상적 사용 | HIGH |
| IAM | IAM-02 | 액세스 키 장기 미교체 (90일+) | HIGH |
| IAM | IAM-03 | 사용자 MFA 미설정 | HIGH |
| IAM | IAM-04 | 와일드카드(*) 과도한 권한 | HIGH |
| IAM | IAM-05 | 사용자 직접 정책 연결 | LOW |
| EC2 | EC2-01 | 보안 그룹 인바운드 과다 허용 (0.0.0.0/0) | HIGH |
| EC2 | EC2-02 | IMDSv2 미강제 | HIGH |
| EC2 | EC2-03 | EBS 볼륨 암호화 누락 | HIGH |
| EC2 | EC2-04 | IAM 역할 미할당 | HIGH |
| EC2 | EC2-05 | User Data 내 민감 정보 포함 | MEDIUM |
| CloudTrail | CT-01 | 조직 추적(Organization Trail) 미설정 | MEDIUM |
| CloudTrail | CT-02 | S3 Object Lock(WORM) 미설정 | MEDIUM |
| CloudTrail | CT-03 | 데이터 이벤트 추적 누락 | HIGH |
| CloudTrail | CT-04 | CloudWatch Logs 연동 누락 | MEDIUM |
| CloudTrail | CT-05 | 단일 리전 설정 | MEDIUM |
| CloudWatch | CW-01 | 보안 이벤트 지표 필터·경보 누락 | HIGH |
| CloudWatch | CW-02 | 로그 그룹 KMS 암호화 미적용 | MEDIUM |
| CloudWatch | CW-03 | 로그 그룹 보존 주기 무제한 | LOW |
| CloudWatch | CW-04 | CloudTrail → CloudWatch 연동 누락 | HIGH |
| CloudWatch | CW-05 | VPC Flow Logs 수집 누락 | HIGH |
| VPC | VPC-01 | 라우팅 테이블 IGW 경로 누락 | MEDIUM |
| VPC | VPC-02 | 퍼블릭 IP 자동 할당 비활성화 | MEDIUM |
| VPC | VPC-03 | NAT 게이트웨이 프라이빗 서브넷 오배치 | MEDIUM |
| VPC | VPC-04 | NACL 아웃바운드 전체 차단 | MEDIUM |

## 설치 및 실행

```bash
# 1. git clone 
git clone https://github.com/aldehrh/AWS-CheckMate.git

# 2. 의존성 설치
pip install -r requirements.txt

# 3. AWS 자격 증명 설정
aws configure
# AWS Access Key ID     : <액세스 키>
# AWS Secret Access Key : <시크릿 키>
# Default region name   : ap-northeast-2
# Default output format : json

# 4. 전체 서비스 점검 + 브라우저 자동 오픈
python main.py

# 5. 특정 서비스만 점검
python main.py --services RDS S3 IAM

# 6. 리전 직접 지정
python main.py --region us-east-1

# 7. 웹 포트 변경 (기본값: 5000)
python main.py --port 8080
```

실행하면 점검 완료 후 브라우저가 자동으로 열립니다.
열리지 않으면 `http://localhost:5000` 을 직접 입력하세요.

## 필요 IAM 권한

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "rds:Describe*",
      "s3:GetBucket*", "s3:ListAllMyBuckets", "s3:GetObjectLockConfiguration",
      "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
      "ec2:Describe*",
      "cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors",
      "logs:DescribeLogGroups", "logs:DescribeMetricFilters",
      "cloudwatch:DescribeAlarmsForMetric",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

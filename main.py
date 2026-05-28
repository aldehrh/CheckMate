"""
main.py — AWS 보안 점검 도구 진입점

────────────────────────────────────────────
사전 준비: aws configure 설정
────────────────────────────────────────────
실행 전에 아래 명령어로 AWS 자격 증명을 먼저 설정하세요.

  $ aws configure

  AWS Access Key ID     : (IAM 사용자 액세스 키)
  AWS Secret Access Key : (IAM 사용자 시크릿 키)
  Default region name   : ap-northeast-2
  Default output format : json

설정 확인:
  $ aws sts get-caller-identity

────────────────────────────────────────────
실행 방법
────────────────────────────────────────────
  python main.py                        # 전체 서비스 점검 + 브라우저 자동 오픈
  python main.py --services RDS S3      # 특정 서비스만 점검
  python main.py --region us-east-1     # 리전 직접 지정 (기본값: aws configure 설정값)
  python main.py --port 8080            # 웹 포트 변경 (기본값: 5000)
"""

import sys
import argparse
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from checkers import ALL_CHECKERS
from report   import run_server

CHECKER_MAP = {cls.SERVICE_NAME: cls for cls in ALL_CHECKERS}


# ── AWS 자격 증명 & 리전 사전 검증 ───────────────────
def validate_aws_config(region_arg: str) -> str:
    """
    aws configure 설정을 검증하고 사용할 리전을 반환.
    문제가 있으면 안내 메시지 출력 후 종료.
    """
    print("  ┌─ AWS 자격 증명 확인 중...")

    session = boto3.Session()

    # 리전 결정: --region 인자 우선, 없으면 aws configure 기본값
    region = region_arg or session.region_name
    if not region:
        print("  │")
        print("  │  ❌ 리전이 설정되지 않았습니다.")
        print("  │")
        print("  │  해결 방법:")
        print("  │    $ aws configure")
        print("  │      Default region name: ap-northeast-2")
        print("  └─────────────────────────────────────────")
        sys.exit(1)

    # 자격 증명 존재 여부 확인
    if not session.get_credentials():
        print("  │")
        print("  │  ❌ AWS 자격 증명(Access Key)이 없습니다.")
        print("  │")
        print("  │  해결 방법:")
        print("  │    $ aws configure")
        print("  │      AWS Access Key ID     : <액세스 키 입력>")
        print("  │      AWS Secret Access Key : <시크릿 키 입력>")
        print("  └─────────────────────────────────────────")
        sys.exit(1)

    # 실제 AWS 연결 테스트
    try:
        sts  = boto3.client("sts", region_name=region)
        info = sts.get_caller_identity()
        print(f"  │  ✅ 계정 ID  : {info['Account']}")
        print(f"  │  ✅ 자격 증명: {info['Arn']}")
        print(f"  │  ✅ 리전     : {region}")
        print("  └─ 검증 완료\n")
        return region

    except NoCredentialsError:
        print("  │")
        print("  │  ❌ 자격 증명이 유효하지 않습니다.")
        print("  │    $ aws configure  (키 재입력)")
        print("  └─────────────────────────────────────────")
        sys.exit(1)

    except ClientError as e:
        code = e.response["Error"]["Code"]
        print("  │")
        print(f"  │  ❌ AWS 연결 실패: {code}")
        if code in ("InvalidClientTokenId", "AuthFailure"):
            print("  │  Access Key 또는 Secret Key가 잘못되었습니다.")
            print("  │    $ aws configure  (키 재입력)")
        elif code == "ExpiredTokenException":
            print("  │  자격 증명이 만료되었습니다. 키를 갱신해 주세요.")
        else:
            print(f"  │  {e}")
        print("  └─────────────────────────────────────────")
        sys.exit(1)

    except Exception as e:
        print(f"  │  ❌ 예상치 못한 오류: {e}")
        print("  └─────────────────────────────────────────")
        sys.exit(1)


# ── 메인 ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AWS 보안 점검 도구")
    parser.add_argument("--region",   default=None,
                        help="AWS 리전 (미입력 시 aws configure 기본값 사용)")
    parser.add_argument("--services", nargs="+", default=list(CHECKER_MAP.keys()),
                        choices=list(CHECKER_MAP.keys()),
                        help="점검할 서비스 (기본값: 전체)")
    parser.add_argument("--port",     type=int, default=5000,
                        help="웹 서버 포트 (기본값: 5000)")
    args = parser.parse_args()

    print("\n" + "═" * 50)
    print("  AWS 보안 점검 도구")
    print("═" * 50 + "\n")

    # 자격 증명 검증
    region = validate_aws_config(args.region)

    # 서비스별 점검 실행
    print(f"  점검 서비스: {', '.join(args.services)}\n")
    reports = []
    for svc in args.services:
        print(f"  ▶ {svc} 점검 중...", end=" ", flush=True)
        try:
            report = CHECKER_MAP[svc](region=region).run()
            reports.append(report)
            print(f"완료  (FAIL={report.fail_count}  WARN={report.warn_count}  PASS={report.pass_count})")
        except Exception as e:
            print(f"오류: {e}")

    if not reports:
        print("\n  점검 결과가 없습니다.")
        sys.exit(1)

    run_server(reports, port=args.port)


if __name__ == "__main__":
    main()

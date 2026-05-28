"""
checkers/vpc_checker.py
Amazon VPC 보안 점검 

점검 항목:
  VPC-01  라우팅 테이블에 IGW 누락 (퍼블릭 서브넷인데 IGW 경로 없음)
  VPC-02  퍼블릭 IP 자동 할당 비활성화된 퍼블릭 서브넷
  VPC-03  NAT 게이트웨이 프라이빗 서브넷 오배치
  VPC-04  Network ACL 아웃바운드 전체 차단
  VPC-05  VPC CIDR 대역 중복 (피어링/VPN 연결 시 충돌 위험)
"""

import boto3
import ipaddress
from .base import BaseChecker, ServiceReport, HIGH, MEDIUM, LOW, PASS, FAIL, WARN


class VPCChecker(BaseChecker):
    SERVICE_NAME = "VPC"

    def run(self) -> ServiceReport:
        report = ServiceReport(service=self.SERVICE_NAME)
        ec2    = boto3.client("ec2", region_name=self.region)

        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
        except Exception as e:
            report.results.append(self._make_result(
                "VPC-00", "VPC 조회", HIGH, "vpc",
                WARN, f"조회 실패: {e}", "ec2:DescribeVpcs 권한 확인"
            ))
            return report

        if not vpcs:
            return report

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            report.results += self._check_igw_route(ec2, vpc_id)      # VPC-01
            report.results += self._check_public_ip_assign(ec2, vpc_id) # VPC-02
            report.results += self._check_nat_placement(ec2, vpc_id)  # VPC-03
            report.results += self._check_nacl_outbound(ec2, vpc_id)  # VPC-04

        report.results += self._check_cidr_overlap(ec2, vpcs)         # VPC-05

        return report

    # VPC-01 ──────────────────────────────────────────
    def _check_igw_route(self, ec2, vpc_id) -> list:
        results = []
        try:
            # IGW 연결 여부 확인
            igws = ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            ).get("InternetGateways", [])

            if not igws:
                # IGW 자체가 없으면 퍼블릭 서브넷 의도 없음 — 점검 불필요
                return results

            igw_id = igws[0]["InternetGatewayId"]

            # 라우팅 테이블에서 IGW 경로 확인
            rts = ec2.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("RouteTables", [])

            has_igw_route = any(
                r.get("GatewayId", "") == igw_id
                for rt in rts for r in rt.get("Routes", [])
            )

            results.append(self._make_result(
                "VPC-01", "라우팅 테이블 IGW 경로", MEDIUM, vpc_id,
                PASS if has_igw_route else FAIL,
                f"IGW({igw_id}) 연결됨, 라우팅 테이블 경로 {'있음' if has_igw_route else '없음'}",
                f"VPC → 라우팅 테이블 → 라우팅 추가 → 대상: 0.0.0.0/0, 게이트웨이: {igw_id}"
                if not has_igw_route else "조치 불필요"
            ))
        except Exception as e:
            results.append(self._make_result(
                "VPC-01", "라우팅 테이블 IGW 경로", MEDIUM, vpc_id,
                WARN, f"조회 실패: {e}", "ec2:DescribeRouteTables 권한 확인"
            ))
        return results

    # VPC-02 ──────────────────────────────────────────
    def _check_public_ip_assign(self, ec2, vpc_id) -> list:
        results = []
        try:
            subnets = ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("Subnets", [])

            rts = ec2.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("RouteTables", [])

            # IGW로 향하는 라우팅이 있는 서브넷 = 퍼블릭 서브넷
            igw_subnet_ids = set()
            for rt in rts:
                has_igw = any("igw-" in r.get("GatewayId", "") for r in rt.get("Routes", []))
                if has_igw:
                    for assoc in rt.get("Associations", []):
                        sid = assoc.get("SubnetId")
                        if sid:
                            igw_subnet_ids.add(sid)

            for subnet in subnets:
                sid       = subnet["SubnetId"]
                auto_pub  = subnet.get("MapPublicIpOnLaunch", False)
                is_public = sid in igw_subnet_ids

                if is_public and not auto_pub:
                    results.append(self._make_result(
                        "VPC-02", "퍼블릭 IP 자동 할당 비활성화", MEDIUM, sid,
                        WARN, "퍼블릭 서브넷인데 퍼블릭 IP 자동 할당 꺼짐 — 인스턴스 외부 접근 불가",
                        f"VPC → 서브넷 → {sid} → 작업 → 서브넷 설정 편집 → 퍼블릭 IPv4 주소 할당 활성화"
                    ))
                else:
                    results.append(self._make_result(
                        "VPC-02", "퍼블릭 IP 자동 할당 비활성화", MEDIUM, sid,
                        PASS, f"퍼블릭 서브넷 여부: {is_public}, 자동 할당: {auto_pub}"
                    ))
        except Exception as e:
            results.append(self._make_result(
                "VPC-02", "퍼블릭 IP 자동 할당 비활성화", MEDIUM, vpc_id,
                WARN, f"조회 실패: {e}", "ec2:DescribeSubnets 권한 확인"
            ))
        return results

    # VPC-03 ──────────────────────────────────────────
    def _check_nat_placement(self, ec2, vpc_id) -> list:
        results = []
        try:
            nats = ec2.describe_nat_gateways(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                         {"Name": "state",  "Values": ["available"]}]
            ).get("NatGateways", [])

            if not nats:
                return results

            # IGW 경로가 있는 서브넷 = 퍼블릭
            rts = ec2.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("RouteTables", [])
            public_subnet_ids = set()
            for rt in rts:
                if any("igw-" in r.get("GatewayId","") for r in rt.get("Routes",[])):
                    for a in rt.get("Associations",[]):
                        if a.get("SubnetId"):
                            public_subnet_ids.add(a["SubnetId"])

            for nat in nats:
                nat_id    = nat["NatGatewayId"]
                subnet_id = nat.get("SubnetId","")
                is_public = subnet_id in public_subnet_ids
                results.append(self._make_result(
                    "VPC-03", "NAT 게이트웨이 배치 위치", MEDIUM, nat_id,
                    PASS if is_public else FAIL,
                    f"서브넷: {subnet_id} ({'퍼블릭 ✓' if is_public else '프라이빗 ✗ — NAT가 인터넷 접근 불가'})",
                    f"VPC → NAT 게이트웨이 → {nat_id} 삭제 후 퍼블릭 서브넷에 재생성"
                    if not is_public else "조치 불필요"
                ))
        except Exception as e:
            results.append(self._make_result(
                "VPC-03", "NAT 게이트웨이 배치 위치", MEDIUM, vpc_id,
                WARN, f"조회 실패: {e}", "ec2:DescribeNatGateways 권한 확인"
            ))
        return results

    # VPC-04 ──────────────────────────────────────────
    def _check_nacl_outbound(self, ec2, vpc_id) -> list:
        results = []
        try:
            nacls = ec2.describe_network_acls(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            ).get("NetworkAcls", [])

            for nacl in nacls:
                nacl_id   = nacl["NetworkAclId"]
                outbound  = [e for e in nacl.get("Entries", []) if e.get("Egress")]
                # 규칙 번호 오름차순 정렬
                outbound.sort(key=lambda x: x.get("RuleNumber", 9999))

                # 첫 번째로 적용되는 규칙 확인
                first_rule = outbound[0] if outbound else None
                if first_rule:
                    action  = first_rule.get("RuleAction","")
                    proto   = first_rule.get("Protocol","-1")
                    cidr    = first_rule.get("CidrBlock","?")
                    rnum    = first_rule.get("RuleNumber")
                    all_deny = (action == "deny" and proto == "-1" and cidr == "0.0.0.0/0")
                    results.append(self._make_result(
                        "VPC-04", "NACL 아웃바운드 차단", MEDIUM, nacl_id,
                        FAIL if all_deny else PASS,
                        f"규칙{rnum}: {action.upper()} 프로토콜={proto} 대상={cidr}"
                        + (" — 모든 아웃바운드 차단됨" if all_deny else ""),
                        f"VPC → 네트워크 ACL → {nacl_id} → 아웃바운드 규칙 편집\n"
                        f"→ 규칙 100: 모든 트래픽 허용(ALLOW) 추가"
                        if all_deny else "조치 불필요"
                    ))
                else:
                    results.append(self._make_result(
                        "VPC-04", "NACL 아웃바운드 차단", MEDIUM, nacl_id,
                        WARN, "아웃바운드 규칙 없음", "NACL 아웃바운드 허용 규칙 추가 필요"
                    ))
        except Exception as e:
            results.append(self._make_result(
                "VPC-04", "NACL 아웃바운드 차단", MEDIUM, vpc_id,
                WARN, f"조회 실패: {e}", "ec2:DescribeNetworkAcls 권한 확인"
            ))
        return results

    # VPC-05 ──────────────────────────────────────────
    def _check_cidr_overlap(self, ec2, vpcs) -> list:
        results = []
        try:
            cidr_map = {}  # vpc_id → list of networks
            for vpc in vpcs:
                vpc_id    = vpc["VpcId"]
                cidrs     = [vpc.get("CidrBlock","")]
                for assoc in vpc.get("CidrBlockAssociationSet", []):
                    c = assoc.get("CidrBlock","")
                    if c and c not in cidrs:
                        cidrs.append(c)
                cidr_map[vpc_id] = [ipaddress.ip_network(c, strict=False) for c in cidrs if c]

            vpc_ids = list(cidr_map.keys())
            for i in range(len(vpc_ids)):
                for j in range(i+1, len(vpc_ids)):
                    a_id, b_id = vpc_ids[i], vpc_ids[j]
                    overlaps = []
                    for na in cidr_map[a_id]:
                        for nb in cidr_map[b_id]:
                            if na.overlaps(nb):
                                overlaps.append(f"{na} ↔ {nb}")
                    if overlaps:
                        results.append(self._make_result(
                            "VPC-05", "VPC CIDR 대역 중복", MEDIUM, f"{a_id} ↔ {b_id}",
                            WARN, "CIDR 겹침: " + ", ".join(overlaps) + " — VPC 피어링/VPN 연결 불가",
                            "VPC → 내 VPC → CIDR 편집 → 겹치지 않는 새 보조 CIDR 추가 후 서브넷 재구성"
                        ))
                    else:
                        results.append(self._make_result(
                            "VPC-05", "VPC CIDR 대역 중복", MEDIUM, f"{a_id} ↔ {b_id}",
                            PASS, "CIDR 대역 겹침 없음"
                        ))
        except Exception as e:
            results.append(self._make_result(
                "VPC-05", "VPC CIDR 대역 중복", MEDIUM, "vpc",
                WARN, f"조회 실패: {e}", "ec2:DescribeVpcs 권한 확인"
            ))
        return results

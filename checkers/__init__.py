from .rds_checker        import RDSChecker
from .s3_checker         import S3Checker
from .iam_checker        import IAMChecker
from .ec2_checker        import EC2Checker
from .cloudtrail_checker import CloudTrailChecker
from .cloudwatch_checker import CloudWatchChecker
from .vpc_checker        import VPCChecker

ALL_CHECKERS = [RDSChecker, S3Checker, IAMChecker, EC2Checker,
                CloudTrailChecker, CloudWatchChecker, VPCChecker]

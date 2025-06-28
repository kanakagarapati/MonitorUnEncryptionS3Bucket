import boto3
import logging
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ANSI escape code for red text
RED = "\033[91m"
RESET = "\033[0m"

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    substring = "kanaka-s3-bucket"

    try:
        buckets_response = s3.list_buckets()
        unencrypted_buckets = []

        for bucket in buckets_response['Buckets']:
            bucket_name = bucket['Name']

            if substring not in bucket_name:
                continue

            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                logger.info(f"{bucket_name} is encrypted with: {rules}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    logger.warning(f"{RED}{bucket_name} is NOT encrypted{RESET}")
                    unencrypted_buckets.append(bucket_name)
                else:
                    logger.error(f"Error checking bucket {bucket_name}: {e}")
        
        if unencrypted_buckets:
            logger.info("Unencrypted Buckets Detected:")
            for bucket in unencrypted_buckets:
                logger.info(f"{RED} - {bucket}{RESET}")
        else:
            logger.info("All filtered buckets have server-side encryption enabled.")

    except Exception as e:
        logger.error(f"Unhandled exception: {e}")

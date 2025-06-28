# MonitorUnEncryptionS3Bucket
# Monitor and Manage S3 Bucket Encryption using AWS Lambda & Boto3

This project sets up an AWS Lambda function that detects unencrypted S3 buckets (i.e., those without default server-side encryption) and logs their names. It also includes optional scripts to disable default encryption for specific buckets.

---

## 📌 Features

- ✅ Lists all S3 buckets with names containing a specific keyword (e.g., `kanaka-s3-bucket`)
- Created 3 S3 buckets
- 
| Instance Name              | Encrypted status  |
|----------------------------|-------------------|
| kanaka-s3-bucket1          |       Yes         |
| kanaka-s3-bucket2          |       Yes         |
| kanaka-s3-bucket3          |        No         |

- bucket 1
- ![image](https://github.com/user-attachments/assets/3249cf21-f700-40b1-8591-20974ac3bda8)

- bucket 2
- ![image](https://github.com/user-attachments/assets/c79e877a-5746-4a04-8c3b-f8e2371c747b)

- bucket 3
- ![image](https://github.com/user-attachments/assets/985217c9-e150-4d72-8c03-3c80854f23f8)


---

## 🧩 Prerequisites

- AWS Account
- IAM Role with the following permissions:
  - `s3:ListAllMyBuckets`
  - `s3:GetBucketEncryption`
  - (optional) `s3:DeleteBucketEncryption` for disabling SSE
- Python 3.x (for local script testing)
- AWS CLI (optional but recommended)

---

### ✅ 2. IAM Role for Lambda

Create a new IAM role named: **kanakaManoj-IAM-readonly-lambda**
![image](https://github.com/user-attachments/assets/597b457d-99fc-4608-8cfa-bf76c4e1b1f1)

![image](https://github.com/user-attachments/assets/4474c7df-1fb9-47b0-95c7-68fe4466ca78)
![image](https://github.com/user-attachments/assets/fb84ebc2-2397-4110-8488-a3b0dcdfb3d7)

Attach the following AWS-managed policy:
- `AmazonS3ReadOnlyAccess`
![image](https://github.com/user-attachments/assets/de50ddd1-940e-4fdf-9235-bd1a72997d79)



This will grant Lambda full access to describe, start, and stop EC2 instances.

---

### ✅ 3. Lambda Function Configuration

- **Runtime**: Python 3.11
- **Handler**: `KanakaManoj-DetectUnencryptedS3Buckets`
- **Deploy Code**: Use inline editor or upload ZIP
![image](https://github.com/user-attachments/assets/232a074a-2b67-4c46-9320-72daa98167e0)


```python
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

```

---

## 🧪 Testing
![image](https://github.com/user-attachments/assets/1286b8d0-8815-4836-a882-9ba6410cf385)


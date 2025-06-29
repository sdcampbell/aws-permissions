# aws-permissions
Uses brute force to enumerate AWS permissions with discovered credentials.

This script was taken from the [CloudPEASS](https://raw.githubusercontent.com/carlospolop/CloudPEASS/refs/heads/main/src/aws/awsbruteforce.py) project and extensively modified to meet my needs.

# Usage

```bash
python3 aws-permissions.py -h
usage: aws-permissions.py [-h] [-d] [-r REGION] [-p PROFILE] [-s [SERVICES ...]] [-t THREADS]

AWS Brute Force Permission Enumeration Tool

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug output
  -r, --region REGION   AWS region (default: us-east-1)
  -p, --profile PROFILE
                        AWS profile (default: default)
  -s, --services [SERVICES ...]
                        AWS services to test (default: all services)
  -t, --threads THREADS
                        Number of threads (default: 10)
```

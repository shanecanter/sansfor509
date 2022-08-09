#!/usr/bin/env python3
# AWS Default Cloudtrail Download script for FOR509
# This script will dump the last 90 days of CloudTrail logs from the AWS maintained trail
# For org created trails in buckets you will need to download that bucket
# Copyright: David Cowen 2021

from __future__ import print_function
import boto3, argparse, os, json, time, datetime
from botocore.exceptions import ClientError
from dateutil.tz import tzlocal
from sys import *

def main(args):
    access_key_id = args.access_key_id
    secret_access_key = args.secret_key
    session_token = args.session_token

    if args.access_key_id is None or args.secret_key is None:
        print('IAM keys not passed in as arguments, enter them below:')
        access_key_id = input('  Access Key ID: ')
        secret_access_key = input('  Secret Access Key: ')
        session_token = input('  Session Token (Leave blank if none): ')
        if session_token.strip() == '':
            session_token = None

    # Get account ID
    sts_client = boto3.client(
        "sts", 
        aws_access_key_id=access_key_id, 
        aws_secret_access_key=secret_access_key, 
        aws_session_token=session_token
        )
    account_id = sts_client.get_caller_identity()["Account"]

    # Get file time
    file_time = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    # String format file name using account ID and file time
    out_file = "{0}_{1}_90days.json".format(file_time, account_id)
    print("Output File: {0}".format(out_file))

    # Begin permissions enumeration
    ct_client = boto3.client(
        'cloudtrail',
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token
    )
    paginator = ct_client.get_paginator('lookup_events')
    StartingToken = None
    total_logs = 0
    page_iterator = paginator.paginate(
        LookupAttributes=[],
        PaginationConfig={'PageSize':50, 'StartingToken':StartingToken})
    with open(out_file,"w") as cloudTraillogs:
        for page in page_iterator:
            for event in page["Events"]:
                event["EventTime"] = event["EventTime"].astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                json.dump(event, cloudTraillogs)
                        
            try:
                token_file = open("token","w") 
                token_file.write(page["NextToken"]) 
                StartingToken = page["NextToken"]
            except KeyError:
                exit()

            stdout.write("Total Logs Downloaded: {}\r".format(total_logs))
            stdout.flush()           
            total_logs = total_logs + 50
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script will fetch the last 90 days of cloudtrail logs.')
    parser.add_argument('--access-key-id', required=False, default=None, help='The AWS access key ID to use for authentication.')
    parser.add_argument('--secret-key', required=False, default=None, help='The AWS secret access key to use for authentication.')
    parser.add_argument('--session-token', required=False, default=None, help='The AWS session token to use for authentication, if there is one.')

    args = parser.parse_args()
    main(args)

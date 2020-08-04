#!/usr/bin/python
"""
Module to get MFA authenticated session tokens
"""


import io
import json
import datetime
import contextlib
import collections
import sys
import configparser
import os
import logging

import click
import keyring
import boto3
import ykman.cli.__main__

# Restore logger, set by ykman.cli.__main__ import
logging.disable(logging.NOTSET)

UTC = datetime.timezone.utc

AWSCred = collections.namedtuple("AWSCred", "access_key_id secret_access_key")


class AWSCredSession:
    """
    Helper for cached (on keyring) AWS Credential Session Class
    """

    def __init__(self, awscred, session_token, expiration, label):
        self.awscred = awscred
        self.session_token = session_token
        self.expiration = expiration
        self.label = label

    def json_credentials(self):
        """
        JSON output for aws credential process
        """
        return json.dumps(
            {
                "Version": 1,
                "AccessKeyId": self.awscred.access_key_id,
                "SecretAccessKey": self.awscred.secret_access_key,
                "SessionToken": self.session_token,
                "Expiration": self.expiration.isoformat(),
            }
        )

    @classmethod
    def get_cached_session(cls, label):
        """
        Factory to generate AWSCredSession object from cache
        """
        cached_session = keyring.get_password("aws_credential_process", label)
        if cached_session is not None:
            logging.info("Cache hit for session %s", label)
            cached_session = json.loads(cached_session)
            cached_session["expiration"] = datetime.datetime.strptime(
                cached_session["expiration"], "%Y-%m-%dT%H:%M:%S%z"
            )
            # use a small margin to prevent working with an almost expired token
            margin = datetime.timedelta(seconds=10)
            logging.info(
                "Check expiration %s > %s",
                cached_session["expiration"],
                datetime.datetime.now(UTC) - margin,
            )
            if cached_session["expiration"] > (datetime.datetime.now(UTC) - margin):
                return cls(
                    expiration=cached_session["expiration"],
                    awscred=AWSCred(
                        cached_session["access_key_id"],
                        cached_session["secret_access_key"],
                    ),
                    session_token=cached_session["session_token"],
                    label=label,
                )
        logging.info("Cache miss for session %s", label)
        return None

    @classmethod
    def load_from_credentials(cls, credentials, label):
        """
        Factory to generate AWSCredSession object from Credentials structure (from API)
        """
        result = cls(
            expiration=credentials["Expiration"],
            awscred=AWSCred(credentials["AccessKeyId"], credentials["SecretAccessKey"]),
            session_token=credentials["SessionToken"],
            label=label,
        )
        keyring.set_password(
            "aws_credential_process",
            label,
            json.dumps(
                {
                    "expiration": result.expiration.isoformat(),
                    "access_key_id": result.awscred.access_key_id,
                    "secret_access_key": result.awscred.secret_access_key,
                    "session_token": result.session_token,
                }
            ),
        )
        return result


def ykman_main(*args):
    """
    Helper function for ykman (yubikey manager) to get oath codes
    """
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        with contextlib.redirect_stdout(stdout):
            try:
                ykman.cli.__main__.cli.main(args=args)
            except SystemExit:
                pass
    return stdout.getvalue().splitlines(), stderr.getvalue().splitlines()


def get_mfa_session(
    access_key, duration_seconds=None, serial_number=None, token_code=None
):
    """
    Get MFA enabled session
    """
    request = {}
    if duration_seconds is not None:
        request["DurationSeconds"] = duration_seconds

    request["SerialNumber"] = serial_number
    request["TokenCode"] = token_code()

    client = boto3.client(
        "sts",
        aws_access_key_id=access_key.access_key_id,
        aws_secret_access_key=access_key.secret_access_key,
    )

    response = client.get_session_token(**request)

    mfa_session = AWSCredSession.load_from_credentials(
        response["Credentials"], access_key.access_key_id + "-mfa-session"
    )
    return mfa_session


def get_mfa_session_cached(
    access_key, duration_seconds=None, serial_number=None, token_code=None
):
    """
    Get MFA enabled session with caching
    """
    mfa_session = AWSCredSession.get_cached_session(
        access_key.access_key_id + "-mfa-session"
    )

    if mfa_session is None:
        mfa_session = get_mfa_session(
            access_key, duration_seconds, serial_number, token_code
        )

    return mfa_session


def get_assume_session(access_key, session, role_arn, duration_seconds=None):
    """
    Get session for assumed role
    """
    request = {"RoleArn": role_arn, "RoleSessionName": "aws_credential_process"}

    if duration_seconds is not None:
        request["DurationSeconds"] = duration_seconds

    client = boto3.client(
        "sts",
        aws_access_key_id=session.awscred.access_key_id,
        aws_secret_access_key=session.awscred.secret_access_key,
        aws_session_token=session.session_token,
    )

    response = client.assume_role(**request)

    assume_session = AWSCredSession.load_from_credentials(
        response["Credentials"],
        "{}-assume-session-{}".format(access_key.access_key_id, role_arn),
    )

    return assume_session


def get_assume_session_cached(access_key, session, role_arn, duration_seconds):
    """
    Get session for assumed role with caching
    """
    assume_session = AWSCredSession.get_cached_session(
        "{}-assume-session-{}".format(access_key.access_key_id, role_arn)
    )

    if assume_session is None:
        assume_session = get_assume_session(
            access_key, session, role_arn, duration_seconds
        )
    return assume_session


def get_credentials(section):
    """
    Return default credentials as specified in ~/.aws/credentials
    """
    config = configparser.ConfigParser()
    config.read(os.path.expanduser("~/.aws/credentials"))
    if section in config:
        return (
            config[section].get("aws_access_key_id"),
            config[section].get("aws_secret_access_key"),
        )
    return (None, None)


@click.command()
@click.option("--access-key-id")
@click.option("--secret-access-key")
@click.option("--mfa-oath-slot")
@click.option("--mfa-serial-number", required=True)
@click.option("--mfa-session-duration", type=int)
@click.option("--assume-session-duration", type=int)
@click.option("--assume-role-arn")
@click.option("--force-renew", is_flag=True, default=False)
@click.option("--credentials-section", default="default")
@click.option("--log-file")
def main(
    access_key_id,
    mfa_serial_number,
    mfa_oath_slot,
    mfa_session_duration=None,
    secret_access_key=None,
    assume_session_duration=None,
    assume_role_arn=None,
    force_renew=False,
    credentials_section="default",
    log_file=None,
):
    """
    Get output suitable for aws credential process
    """
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.DEBUG)

    if access_key_id is None and secret_access_key is None:
        access_key_id, secret_access_key = get_credentials(credentials_section)

    if not access_key_id:
        logging.warning(
            "No --access_key_id supplied and could not load from ~/.aws/credentials."
        )
        sys.exit(1)

    if secret_access_key:
        keyring.set_password("aws_credential_process", access_key_id, secret_access_key)
    else:
        secret_access_key = keyring.get_password(
            "aws_credential_process", access_key_id
        )

    if secret_access_key is None:
        logging.warning(
            "Secret access key is not supplied as argument and couldn't it load from keyring."
        )
        sys.exit(1)

    access_key = AWSCred(access_key_id, secret_access_key)

    def token_code():
        token_code = None
        if mfa_oath_slot:
            stdout, _ = ykman_main("oath", "code", "-s", mfa_oath_slot)

            if len(stdout) == 1:
                (token_code,) = stdout

        if not token_code:
            token_code = str(
                click.prompt(
                    "Cannot get token code from Yubi key, please enter manually",
                    type=int,
                )
            )
        return token_code

    mfa_session_request = (
        access_key,
        mfa_session_duration,
        mfa_serial_number,
        token_code,
    )

    if assume_role_arn:
        if force_renew:
            assume_session = None
        else:
            assume_session = AWSCredSession.get_cached_session(
                "{}-assume-session-{}".format(access_key.access_key_id, assume_role_arn)
            )
        if assume_session is None:

            if force_renew:
                mfa_session = get_mfa_session(*mfa_session_request)
            else:
                mfa_session = get_mfa_session_cached(*mfa_session_request)

            if mfa_session is None:
                logging.warning("Failed to get MFA session")
                sys.exit(1)

            assume_session = get_assume_session(
                access_key, mfa_session, assume_role_arn, assume_session_duration
            )

        if assume_session is None:
            logging.warning("Failed to get assume session")
            sys.exit(1)
        else:
            print(assume_session.json_credentials())
    else:
        if force_renew:
            mfa_session = get_mfa_session(*mfa_session_request)
        else:
            mfa_session = get_mfa_session_cached(*mfa_session_request)

        if mfa_session is None:
            logging.warning("Failed to get MFA session")
            sys.exit(1)
        else:
            print(mfa_session.json_credentials())

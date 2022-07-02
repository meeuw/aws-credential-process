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
import shutil
import time
import warnings
import textwrap

import click
import keyring
import boto3

from cryptography.utils import CryptographyDeprecationWarning

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    import ykman.cli.__main__

import pynentry
import toml

__version__ = "0.16.0"

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

    def serialize_credentials(self, fmt="json"):
        if fmt == "json":
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
        elif fmt == "shell":
            """
            Shell output with AWS_ environment variables
            """
            return textwrap.dedent(
                f"""\
                export AWS_ACCESS_KEY_ID={self.awscred.access_key_id}
                export AWS_SECRET_ACCESS_KEY={self.awscred.secret_access_key}
                export AWS_SESSION_TOKEN={self.session_token}
                """
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
            # use cache:      expiration     >          now        +   margin
            # True:      2020-01-01 12:00:00 > 2020-01-01 11:00:00 + 10 seconds
            # False:     2020-01-01 12:00:00 > 2020-01-01 11:59:51 + 10 seconds
            if cached_session["expiration"] > (datetime.datetime.now(UTC) + margin):
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

    if serial_number:
        request["SerialNumber"] = serial_number
    if token_code:
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


def get_assume_session(
    access_key,
    session,
    role_arn,
    policy_arns,
    policy,
    source_identity,
    duration_seconds=None,
    serial_number=None,
    token_code=None,
):
    """
    Get session for assumed role
    """
    request = {"RoleArn": role_arn, "RoleSessionName": "aws_credential_process"}

    if duration_seconds is not None:
        request["DurationSeconds"] = duration_seconds

    if serial_number:
        request["SerialNumber"] = serial_number

    if token_code:
        request["TokenCode"] = token_code()

    if policy_arns:
        request["PolicyArns"] = list({"arn": v} for v in policy_arns)

    if policy:
        if policy[0] == "@":
            with open(policy[1:]) as f:
                policy = f.read()
        request["Policy"] = policy

    if source_identity:
        request["SourceIdentity"] = source_identity

    if session is None:
        client = boto3.client(
            "sts",
            aws_access_key_id=access_key.access_key_id,
            aws_secret_access_key=access_key.secret_access_key,
        )
    else:
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


def get_assume_session_cached(
    access_key, session, role_arn, policy_arns, policy, source_identity, duration_seconds, serial_number=None, token_code=None
):
    """
    Get session for assumed role with caching
    """
    assume_session = AWSCredSession.get_cached_session(
        "{}-assume-session-{}".format(access_key.access_key_id, role_arn)
    )

    if assume_session is None:
        assume_session = get_assume_session(
            access_key, session, role_arn, policy_arns, policy, source_identity, duration_seconds, serial_number, token_code
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


def traverse_config(config, accumulated, flattened):
    for k, v in config.items():
        if isinstance(v, list):
            for i in v:
                accumulated_copy = accumulated.copy()
                flattened[k] = traverse_config(i, accumulated_copy, flattened)
        else:
            accumulated[k] = v

    return accumulated


def parse_config(config):
    flattened = {}
    traverse_config(config, {}, flattened)
    for pk, pv in flattened.items():
        for k, v in pv.items():
            if isinstance(v, str):
                pv[k] = v.format(section=pk)
    return flattened


def main(
    log_file,
    access_key_id,
    secret_access_key,
    credentials_section,
    mfa_oath_slot,
    pin_entry,
    mfa_session_duration,
    mfa_serial_number,
    assume_role_arn,
    assume_role_policy_arns,
    assume_role_policy,
    assume_role_source_identity,
    force_renew_session,
    force_renew_assume_role,
    assume_session_duration,
    output_format,
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

    if mfa_session_duration is not None:
        mfa_session_duration = int(mfa_session_duration)

    if force_renew_session:
        force_renew_assume_role = True

    def token_code():
        for _ in range(5):
            token_code = None
            if mfa_oath_slot:
                stdout, _ = ykman_main("oath", "accounts", "code", "-s", mfa_oath_slot)

                if len(stdout) == 1:
                    (token_code,) = stdout

            if not token_code and shutil.which(pin_entry):
                with pynentry.PynEntry(executable=pin_entry) as p:
                    p.description = (
                        f"Couldn't get a OATH code for {mfa_oath_slot}, please enter manually.\n"
                        "Confirm as empty or cancel to retry using yubikey."
                    )
                    p.prompt = "aws-credential-process"
                    try:
                        token_code = p.get_pin()
                    except pynentry.PinEntryCancelled:
                        token_code = None
            else:
                time.sleep(1)

            if token_code is not None:
                break

        return token_code

    if mfa_session_duration == 0:
        mfa_session_request = (
            access_key,
            mfa_session_duration,
        )
    else:
        mfa_session_request = (
            access_key,
            mfa_session_duration,
            mfa_serial_number,
            token_code,
        )

    if assume_role_arn:
        if force_renew_assume_role:
            assume_session = None
        else:
            assume_session = AWSCredSession.get_cached_session(
                "{}-assume-session-{}".format(access_key.access_key_id, assume_role_arn)
            )
        if assume_session is None:

            if mfa_session_duration == 0:
                mfa_session = None
            else:
                if force_renew_session:
                    mfa_session = get_mfa_session(*mfa_session_request)
                else:
                    mfa_session = get_mfa_session_cached(*mfa_session_request)

                if mfa_session is None:
                    logging.warning("Failed to get MFA session")
                    sys.exit(1)

            if mfa_session_duration == 0:
                assume_session = get_assume_session(
                    access_key,
                    mfa_session,
                    assume_role_arn,
                    assume_role_policy_arns,
                    assume_role_policy,
                    assume_role_source_identity,
                    assume_session_duration,
                    mfa_serial_number,
                    token_code,
                )
            else:
                assume_session = get_assume_session(
                    access_key,
                    mfa_session,
                    assume_role_arn,
                    assume_role_policy_arns,
                    assume_role_policy,
                    assume_role_source_identity,
                    assume_session_duration,
                )

        if assume_session is None:
            logging.warning("Failed to get assume session")
            sys.exit(1)
        else:
            print(assume_session.serialize_credentials(fmt=output_format), end="")
    else:
        if mfa_session_duration == 0:
            logging.warning("Cannot do MFA without session")
            sys.exit(1)

        if force_renew_session:
            mfa_session = get_mfa_session(*mfa_session_request)
        else:
            mfa_session = get_mfa_session_cached(*mfa_session_request)

        if mfa_session is None:
            logging.warning("Failed to get MFA session")
            sys.exit(1)
        else:
            print(mfa_session.serialize_credentials(fmt=output_format), end="")


@click.command()
@click.version_option(__version__)
@click.option("--access-key-id")
@click.option("--secret-access-key")
@click.option(
    "--mfa-oath-slot", help="how the MFA slot is named, check using ykman oath code"
)
@click.option("--mfa-serial-number", help="MFA serial number, see IAM console")
@click.option(
    "--mfa-session-duration",
    type=int,
    help="duration in seconds, use zero to assume role without session",
)
@click.option("--assume-session-duration", help="duration in seconds", type=int)
@click.option("--assume-role-arn", help="IAM Role to be assumed, optional")
@click.option(
    "--assume-role-policy-arns",
    help="Assume role with policy ARN, can be used multiple times",
    multiple=True,
)
@click.option(
    "--assume-role-policy",
    help="Assume role with this policy, you can use a filename if this value starts with @",
)
@click.option(
    "--assume-role-source-identity",
    help="The source identity specified by the principal that is calling the AssumeRole operation.",
)
@click.option("--force-renew-session", is_flag=True)
@click.option("--force-renew-assume-role", is_flag=True)
@click.option("--credentials-section", help="Use this section from ~/.aws/credentials")
@click.option(
    "--pin-entry",
    help="pin-entry helper, should be compatible with Assuan protocol (GPG)",
)
@click.option("--log-file")
@click.option("--config-section", help="Use this section in config-file")
@click.option("--config-file", default="~/.config/aws-credential-process/config.toml")
@click.option(
    "--output-format", default="json", help="Output format, json (default) or shell"
)
def click_main(
    access_key_id,
    mfa_serial_number,
    mfa_oath_slot,
    mfa_session_duration,
    secret_access_key,
    assume_session_duration,
    assume_role_arn,
    assume_role_policy_arns,
    assume_role_policy,
    assume_role_source_identity,
    force_renew_session,
    force_renew_assume_role,
    credentials_section,
    pin_entry,
    log_file,
    config_section,
    config_file,
    output_format,
):
    """
    Get output suitable for aws credential process
    """
    config_file = os.path.expanduser(config_file)
    if config_section:
        if not os.path.exists(config_file):
            click.echo(f"Config file {config_file} doesn't exist.", err=True)
            sys.exit(1)

        with open(config_file) as f:
            flattened = parse_config(toml.load(f))

        if not config_section in flattened:
            click.echo(f"{config_section} not found in config file", err=True)
            sys.exit(1)

        config = flattened[config_section]
    else:
        config = {}

    if log_file:
        config["log_file"] = log_file
    if access_key_id:
        config["access_key_id"] = access_key_id
    if mfa_serial_number:
        config["mfa_serial_number"] = mfa_serial_number
    if mfa_oath_slot:
        config["mfa_oath_slot"] = mfa_oath_slot
    if mfa_session_duration is not None:
        config["mfa_session_duration"] = mfa_session_duration
    if secret_access_key:
        config["secret_access_key"] = secret_access_key
    if assume_session_duration:
        config["assume_session_duration"] = assume_session_duration
    if assume_role_arn:
        config["assume_role_arn"] = assume_role_arn
    if force_renew_session:
        config["force_renew_session"] = force_renew_session
    if force_renew_assume_role:
        config["force_renew_assume_role"] = force_renew_assume_role
    if credentials_section:
        config["credentials_section"] = credentials_section
    if pin_entry:
        config["pin_entry"] = pin_entry
    if assume_role_policy_arns:
        config["assume_role_policy_arns"] = assume_role_policy_arns
    if assume_role_policy:
        config["assume_role_policy"] = assume_role_policy
    if assume_role_source_identity:
        config["assume_role_source_identity"] = assume_role_source_identity
    if output_format:
        config["output_format"] = output_format

    if not config.get("mfa_serial_number"):
        click.echo("Required mfa_serial_number not set", err=True)
        sys.exit(1)

    main(
        config.get("log_file"),
        config.get("access_key_id"),
        config.get("secret_access_key"),
        config.get("credentials_section", "default"),
        config.get("mfa_oath_slot"),
        config.get("pin_entry", "pinentry"),
        config.get("mfa_session_duration"),
        config.get("mfa_serial_number"),
        config.get("assume_role_arn"),
        config.get("assume_role_policy_arns"),
        config.get("assume_role_policy"),
        config.get("assume_role_source_identity"),
        config.get("force_renew_session", False),
        config.get("force_renew_assume_role", False),
        config.get("assume_session_duration"),
        config.get("output_format"),
    )

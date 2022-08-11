"""
Tests for aws-credential-process
"""
import datetime
import unittest.mock
import tempfile
import pathlib
import textwrap

import toml
import freezegun
import click.testing
import moto
import aws_credential_process
import pytest
import keyring


class MemKeyring(keyring.backend.KeyringBackend):
    priority = 1

    def __init__(self):
        self.passwords = {}

    def create_if_not_exist(self, servicename):
        if not servicename in self.passwords:
            self.passwords[servicename] = {}

    def set_password(self, servicename, username, password):
        self.create_if_not_exist(servicename)
        self.passwords[servicename][username] = password

    def get_password(self, servicename, username):
        print(f"servicename: {servicename}, username: {username}")
        self.create_if_not_exist(servicename)
        return self.passwords[servicename].get(username)

    def delete_password(self, servicename, username):
        self.create_if_not_exist(servicename)
        del self.passwords[servicename][username]


UTC = datetime.timezone.utc


@pytest.fixture
def awscredsession():
    return aws_credential_process.AWSCredSession(
        aws_credential_process.AWSCred(
            access_key_id="access_key_id", secret_access_key="secret_access_key"
        ),
        "session_token",
        datetime.datetime(2022, 8, 11),
        "label",
    )


def test_load_from_credentials():
    """
    Test load_from_credentials
    """
    keyring.set_keyring(MemKeyring())
    assert (
        "1234"
        == aws_credential_process.AWSCredSession.load_from_credentials(
            {
                "Expiration": datetime.datetime(2019, 1, 1, 12, tzinfo=UTC),
                "AccessKeyId": "1234",
                "SecretAccessKey": "1234",
                "SessionToken": "1234",
            },
            "test",
        ).session_token
    )
    assert (
        keyring.get_password("aws_credential_process", "test")
        == '{"expiration": "2019-01-01T12:00:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}'
    )


def test_get_cached_session():
    """
    Test get_cached_session from keyring
    """
    keyring.set_keyring(MemKeyring())
    keyring.set_password(
        "aws_credential_process",
        "test",
        '{"expiration": "2019-01-01T12:00:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}',
    )
    with freezegun.freeze_time("2019-01-01"):
        a = aws_credential_process.AWSCredSession.get_cached_session("test")
        assert a.expiration == datetime.datetime(2019, 1, 1, 12, 0, tzinfo=UTC)
    a = aws_credential_process.AWSCredSession.get_cached_session("test")
    assert a is None


def test_main(monkeypatch):
    keyring.set_keyring(MemKeyring())

    def mock_ykman(args):
        print("123456")

    monkeypatch.setattr("ykman.cli.__main__.cli.main", mock_ykman)

    with moto.mock_sts():
        runner = click.testing.CliRunner()
        result = runner.invoke(
            aws_credential_process.click_main,
            [
                "--access-key-id",
                "test-access-key-id",
                "--secret-access-key",
                "test-secret-access-key-id",
                "--mfa-oath-slot",
                "test-mfa-oath-slot",
                "--mfa-serial-number",
                "test-mfa-serial-number",
                "--mfa-session-duration",
                "900",
                "--assume-session-duration",
                "900",
                "--assume-role-arn",
                "test-assume-role-arn",
            ],
        )
    assert not result.exception, result.output
    assert result.exit_code == 0, result.output


def test_mock_get_credentials(monkeypatch):
    mock_get_credentials = unittest.mock.MagicMock(return_value=(None, None))
    monkeypatch.setattr("aws_credential_process.get_credentials", mock_get_credentials)
    runner = click.testing.CliRunner()
    result = runner.invoke(
        aws_credential_process.click_main,
        [
            "--mfa-oath-slot",
            "test-mfa-oath-slot",
            "--mfa-serial-number",
            "test-mfa-serial-number",
        ],
    )
    assert result.exit_code == 1, result.output
    mock_get_credentials.assert_called()


def test_get_credentials(monkeypatch):
    with tempfile.NamedTemporaryFile() as credentials:
        credentials.write(
            textwrap.dedent(
                """
            [default]
            aws_access_key_id = aws_access_key_id
            aws_secret_access_key = aws_secret_access_key
        """
            ).encode("utf8")
        )
        credentials.flush()
        expanduser = unittest.mock.MagicMock(return_value=credentials.name)
        monkeypatch.setattr("os.path.expanduser", expanduser)
        assert aws_credential_process.get_credentials("default") == (
            "aws_access_key_id",
            "aws_secret_access_key",
        )
        assert aws_credential_process.get_credentials("invalid") == (None, None)


def test_parse_config():
    """
    Test parse_config to see if the configurations are properly folded
    """
    assert aws_credential_process.parse_config(
        {
            "org": [
                {
                    "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
                    "credentials_section": 123457890123,
                    "mfa_oath_slot": "Amazon Web Services:user@123457890123",
                    "dept": [
                        {
                            "assume_role_arn": "arn:aws:iam::{section}:role/Department/Role",
                            "3210987654321": [{}],
                            "7890123456789": [{}],
                        }
                    ],
                    "3456789012345": [
                        {"assume_role_arn": "arn:aws:iam::{section}:role/Other/Role"}
                    ],
                }
            ],
            "other": [
                {
                    "mfa_oath_slot": "Amazon Web Services:user@{section}",
                    "mfa_serial_number": "arn:aws:iam::{section}:mfa/user",
                    "credentials_section": "{section}",
                }
            ],
        }
    ) == {
        "3210987654321": {
            "credentials_section": 123457890123,
            "mfa_oath_slot": "Amazon Web Services:user@123457890123",
            "assume_role_arn": "arn:aws:iam::3210987654321:role/Department/Role",
            "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
        },
        "3456789012345": {
            "credentials_section": 123457890123,
            "mfa_oath_slot": "Amazon Web Services:user@123457890123",
            "assume_role_arn": "arn:aws:iam::3456789012345:role/Other/Role",
            "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
        },
        "7890123456789": {
            "credentials_section": 123457890123,
            "mfa_oath_slot": "Amazon Web Services:user@123457890123",
            "assume_role_arn": "arn:aws:iam::7890123456789:role/Department/Role",
            "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
        },
        "dept": {
            "credentials_section": 123457890123,
            "mfa_oath_slot": "Amazon Web Services:user@123457890123",
            "assume_role_arn": "arn:aws:iam::dept:role/Department/Role",
            "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
        },
        "org": {
            "credentials_section": 123457890123,
            "mfa_oath_slot": "Amazon Web Services:user@123457890123",
            "mfa_serial_number": "arn:aws:iam::123457890123:mfa/user",
        },
        "other": {
            "credentials_section": "other",
            "mfa_oath_slot": "Amazon Web Services:user@other",
            "mfa_serial_number": "arn:aws:iam::other:mfa/user",
        },
    }


def test_version():
    """
    Make sure the version from pyproject.toml and aws_credential_process are equal
    """
    path = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    pyproject = toml.loads(open(str(path)).read())
    assert aws_credential_process.__version__ == pyproject["tool"]["poetry"]["version"]


def test_awscredsession(awscredsession):
    assert (
        awscredsession.serialize_credentials("json")
        == '{"Version": 1, "AccessKeyId": "access_key_id", "SecretAccessKey": "secret_access_key", "SessionToken": "session_token", "Expiration": "2022-08-11T00:00:00"}'
    )
    assert awscredsession.serialize_credentials("shell") == textwrap.dedent(
        """\
            export AWS_ACCESS_KEY_ID=access_key_id
            export AWS_SECRET_ACCESS_KEY=secret_access_key
            export AWS_SESSION_TOKEN=session_token
        """
    )
    with pytest.raises(AssertionError):
        awscredsession.serialize_credentials("invalid")


def test_get_assume_session_cached(awscredsession):
    """
    Test get_assume_session_cached
    """
    keyring.set_keyring(MemKeyring())
    with moto.mock_sts():
        assert isinstance(
            aws_credential_process.get_assume_session_cached(
                awscredsession.awscred,
                None,
                "arn:aws:iam::account:role/role-name-with-path",
                ["arn:aws:iam::account:policy/policy-name-with-path"],
                None,
                "source_identity",
                3600,
                "serial_number",
                lambda: "123456",
            ).session_token,
            str,
        )

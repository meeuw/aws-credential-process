import datetime
import unittest.mock
import freezegun
import click.testing
import moto
import aws_credential_process

UTC = datetime.timezone.utc


def test_load_from_credentials(monkeypatch):
    keyring_set_password = unittest.mock.MagicMock()
    monkeypatch.setattr("keyring.set_password", keyring_set_password)
    a = aws_credential_process.AWSCredSession.load_from_credentials(
        {
            "Expiration": datetime.datetime(2019, 1, 1, 12, tzinfo=UTC),
            "AccessKeyId": "1234",
            "SecretAccessKey": "1234",
            "SessionToken": "1234",
        },
        "test",
    )
    assert keyring_set_password.mock_calls == [
        unittest.mock.call(
            "aws_credential_process",
            "test",
            '{"expiration": "2019-01-01T12:00:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}',
        )
    ]


def test_get_cached_session(monkeypatch):
    keyring_get_password = unittest.mock.MagicMock()
    keyring_get_password.return_value = '{"expiration": "2019-01-01T12:00:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}'
    monkeypatch.setattr("keyring.get_password", keyring_get_password)
    with freezegun.freeze_time("2019-01-01"):
        a = aws_credential_process.AWSCredSession.get_cached_session("test")
        assert a.expiration == datetime.datetime(2019, 1, 1, 12, 0, tzinfo=UTC)
    a = aws_credential_process.AWSCredSession.get_cached_session("test")
    assert a is None


def test_main(monkeypatch):
    keyring_get_password = unittest.mock.MagicMock()
    keyring_get_password.return_value = '{"expiration": "2019-01-01T12:00:00+00:00", "access_key_id": "1234", "secret_access_key": "1234", "session_token": "1234"}'
    monkeypatch.setattr("keyring.get_password", keyring_get_password)

    keyring_set_password = unittest.mock.MagicMock()
    monkeypatch.setattr("keyring.set_password", keyring_set_password)

    def mock_ykman(args):
        print("123456")

    monkeypatch.setattr("ykman.cli.__main__.cli.main", mock_ykman)

    with moto.mock_sts():
        runner = click.testing.CliRunner()
        result = runner.invoke(
            aws_credential_process.main,
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

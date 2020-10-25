# README

## Description

Script to use as `credential_process` for the AWS CLI (including boto3), it
caches your MFA session in a keyring and can use a Yubi key to authenticate.

This is useful if you are required to use MFA authenticated sessions or need
an MFA authenticated session to assume a role.

## Installing

You can install aws-credential-process using pip:

```bash
pip install aws_credential_process
```

I recommend to install aws-credential-process in a virtualenv:

```bash
virtualenv ~/venv/aws_credential_process
~/venv/aws_credential_process/bin/pip install aws_credential_process
```

After the above commands you should be able to run `~/venv/aws_credential_process/bin/aws-credential-process`

## Usage

You can use the following arguments to start aws-credential-process:

```
Usage: aws-credential-process [OPTIONS]

  Get output suitable for aws credential process

Options:
  --access-key-id TEXT
  --secret-access-key TEXT
  --mfa-oath-slot TEXT
  --mfa-serial-number TEXT        [required]
  --mfa-session-duration INTEGER
  --assume-session-duration INTEGER
  --assume-role-arn TEXT
  --force-renew
  --credentials-section TEXT
  --pin-entry TEXT
  --log-file TEXT
  --help                          Show this message and exit.
```

aws-credential-process is meant to be used as `credential_process` in your
`.aws/config` file. For example:

```ini
[profile yourprofile]
credential_process = /home/user/venv/aws_credential_process/bin/aws-credential-process --mfa-oath-slot "Amazon Web Services:test@example.com" --mfa-serial-number arn:aws:iam::123456789012:mfa/john.doe --assume-role-arn arn:aws:iam::123456789012:role/YourRole
```

If you've supplied the secret-access-key once you can omit it with the next call,
it will be cached in your keyring.

When you don't supply the access-key-id it will be loaded from `~/.aws/credentials`.
You can use another section than "default" by using the credentials-section argument.

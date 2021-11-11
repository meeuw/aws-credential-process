# README

## Description

Script to use as `credential_process` for the AWS CLI (including boto3), it
caches your MFA session in a keyring and can use a Yubi key to authenticate.

This is useful if you are required to use MFA authenticated sessions or need
an MFA authenticated session to assume a role.

## Installing

### Generic

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


### MacOS (Homebrew)

```bash
brew install meeuw/aws-credential-process/aws-credential-process
```

## Usage

You can use the following arguments to start aws-credential-process:

```
Usage: aws-credential-process [OPTIONS]

  Get output suitable for aws credential process

Options:
  --version                       Show the version and exit.
  --access-key-id TEXT
  --secret-access-key TEXT
  --mfa-oath-slot TEXT            how the MFA slot is named, check using ykman
                                  oath code

  --mfa-serial-number TEXT        MFA serial number, see IAM console
  --mfa-session-duration INTEGER  duration in seconds, use zero to assume role
                                  without session

  --assume-session-duration INTEGER
                                  duration in seconds
  --assume-role-arn TEXT          IAM Role to be assumed, optional
  --assume-role-policy-arns TEXT  Assume role with policy ARN, can be used
                                  multiple times

  --assume-role-policy TEXT       Assume role with this policy, you can use a
                                  filename if this value starts with @

  --force-renew-session
  --force-renew-assume-role
  --credentials-section TEXT      Use this section from ~/.aws/credentials
  --pin-entry TEXT                pin-entry helper, should be compatible with
                                  Assuan protocol (GPG)

  --log-file TEXT
  --config-section TEXT           Use this section in config-file
  --config-file TEXT
  --output-format TEXT            Output format, json (default) or shell
  --help                          Show this message and exit.
```

aws-credential-process is meant to be used as `credential_process` in your
`.aws/config` file. For example:

```ini
[profile yourprofile]
credential_process = /home/user/venv/aws_credential_process/bin/aws-credential-process --mfa-oath-slot "Amazon Web Services:test@example.com" --mfa-serial-number arn:aws:iam::123456789012:mfa/john.doe --assume-role-arn arn:aws:iam::123456789012:role/YourRole
```

You can also use aws-credential-process to generate exports for your shell which
is supported by many tools:

```bash
$ $(/home/user/venv/aws_credential_process/bin/aws-credential-process --mfa-oath-slot "Amazon Web Services:test@example.com" --mfa-serial-n  umber arn:aws:iam::123456789012:mfa/john.doe --assume-role-arn arn:aws:iam::123456789012:role/YourRole --output-format shell)
```

## Configuration

aws-credential-process can also use a configuration file, the default location of
this file is `~/.config/aws-credential-process/config.toml`. This file contains
defaults so you don't have to supply all of the arguments.

You can configure a default pin-entry program like:

```toml
pin_entry = /usr/local/bin/pin_entry
```

Or you can define multiple config-sections:

```toml
[123457890123]
mfa_oath_slot="Amazon Web Services:user@123457890123"
assume_role_arn="arn:aws:iam::123457890123:role/Other/Role"
credentials_section="123457890123"
mfa_serial_number="arn:aws:iam::123457890123:mfa/user"

[098765432101]
mfa_oath_slot="Amazon Web Services:user@098765432101"
credentials_section="098765432101"
mfa_serial_number="arn:aws:iam::098765432101:mfa/user"
```

If you need to assume roles from a certain AWS account you'll end up with a lot
of simular entries. To make this simple the configuration can be defined
hierarchical.

```toml
[[org]]
mfa_oath_slot="Amazon Web Services:user@123457890123"
assume_role_arn="arn:aws:iam::{section}:role/Other/Role"
credentials_section="123457890123"
mfa_serial_number="arn:aws:iam::123457890123:mfa/user"

[[org.098765432101]]
[[org.567890123456]]
```

This would be the same as the following configuration:

```toml
[098765432101]
mfa_oath_slot="Amazon Web Services:user@123457890123"
assume_role_arn="arn:aws:iam::098765432101:role/Other/Role"
credentials_section="123457890123"
mfa_serial_number="arn:aws:iam::123457890123:mfa/user"

[567890123456]
mfa_oath_slot="Amazon Web Services:user@123457890123"
assume_role_arn="arn:aws:iam::567890123456:role/Other/Role"
credentials_section="123457890123"
mfa_serial_number="arn:aws:iam::123457890123:mfa/user"
```

With the above configuration aws-credential-process can be used like this in
`~/.aws/config`:

```ini
[profile profile1]
credential_process = /home/user/venv/aws_credential_process/bin/aws-credential-process --config-section=098765432101

[profile profile2]
credential_process = /home/user/venv/aws_credential_process/bin/aws-credential-process --config-section=567890123456
```

## Optional arguments

If you've supplied the secret-access-key once you can omit it with the next call,
it will be cached in your keyring.

When you don't supply the access-key-id it will be loaded from `~/.aws/credentials`.
You can use another section than "default" by using the credentials-section argument.

If you don't specify `*-session-duration` the default value from AWS will be used
(3600 seconds). When `--mfa-session-duration` is set to `0` and you use `--assume-role-arn`
a role will be assumed without using a session. Some API calls can't be made when the role
is assumed using an MFA session.

You can also omit the `--assume-role-arn`, then you can use an MFA authenticated session
using your permanent IAM credentials.

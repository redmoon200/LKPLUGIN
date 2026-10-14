# License module and cloud dashboard

The plugin needs a license key to run. Keys are made on the cloud server (the
vendor side) and checked on the firewall with a public key, so a firewall can
never create keys for itself.

## Key types

| Type | Length | Typical use |
|------|--------|-------------|
| Trial | 30 days | evaluation; a firewall can ask for one itself, once |
| Standard | 365 days | yearly subscription |
| Lifetime | never ends | one-off purchase |

A key may be tied to one firewall (its **installation id**) or work on any
firewall. The installation id looks like `1234-ABCD-5678-EF01`; it is derived
from the firewall's host id (`kern.hostuuid`) and shown on **Layer 7 > License**.

## On the firewall

**Layer 7 > License** shows the state, type, end date, installation id and the
connection to the cloud server. You can paste a key, start the 30-day trial, or
remove the key.

Rules:

- A running license is replaced only by a key that runs **longer** (a renewal).
- A **lifetime** license cannot be replaced.
- A key tied to another firewall, a damaged key and an expired key are refused.
- A dated license stops if the clock is turned back by more than a day (the last
  time seen is kept with a MAC). The cloud server's time fixes it at the next
  check-in.

Without a valid license (none, expired, withdrawn, wrong clock) the plugin is
**locked**:

- its pages open the License page and its APIs answer HTTP 402,
- the engine, DNS filter, proxy, sign-in portal and pf rules are switched off
  (the same as unticking *Enabled*), downloads of lists stop,
- **traffic through the firewall is not touched**: the lock fails open, it never
  cuts the network.

Entering a valid key applies everything again within seconds. A cron job
checks the state every 15 minutes (so an end date is noticed) and reports to the
cloud server once an hour.

## Check-in

Once an hour (and on *Check in and update now*) the firewall sends its
installation id, key, plugin version and host name to
`<server>/api/v1/checkin` and receives the state of its license:

- **withdrawn** (revoked on the dashboard): the firewall locks;
- **reinstated**: it unlocks;
- **replacement key** (issued with *Replace* on the dashboard): installed by the
  firewall itself if it runs longer.

The check-in is optional: a firewall that cannot reach the server keeps working
with the key it has until the key ends.

## Cloud server dashboard

`http://<server>:8090/`, sign in with the admin password (printed once by
`install.sh`; change it with `dashboard.py set-password` or under Settings).

| Page | What it shows |
|------|---------------|
| Overview | last build and its length, source problems, published files, firewalls seen in 24 hours, licenses by state (and those ending within 14 days), requests, disk |
| Feeds | every published file with entries, size and age; every source with its last result; rebuild buttons (everything or one part) with the live build log |
| Firewalls | every firewall that checked in: name, installation id, version, address, license, last check-in |
| Licenses | **generator** (customer, type, optional installation id, note, optional issue date for tests), list with state and which firewall uses each key, copy, revoke / reinstate, replace, CSV export |
| Activity | requests: feed downloads, check-ins, trial requests, errors |
| Settings | trial keys on or off, the public key, password |

Security: PBKDF2 password hash, session cookie (`HttpOnly`, `SameSite=Strict`),
a header that scripts on other sites cannot send, 5 wrong passwords per address
in 10 minutes lock sign-in for a while, strict content security policy. Put the
dashboard port on a management network or behind a firewall rule; it is meant
for the vendor, not for customers. The public port (8080) only offers the feeds,
check-in and trial endpoints and is rate limited.

## The signing key

`/var/lib/l7cloud/license/signing.pem` (mode 0600, created by the first
`install.sh`) signs every key. Back it up offline. Whoever has it can issue
licenses; if it is lost, existing keys keep working but you cannot sign more
with the same trust, and plugins would have to be rebuilt with a new public key.

The matching **public key** is compiled into the plugin
(`PUBKEY_B64` in `License.php`) and shown in the dashboard under Settings. If you
install your own cloud server, take its public key from Settings and build the
plugin with it.

## Key format

22 bytes (version, type, issue day, length in days, 8 random key id bytes, 8
bytes binding) plus an Ed25519 signature (64 bytes) over `L7LIC1\0` and those
bytes, written as base32 in groups of five. Ed25519 is verified with the
`openssl` command (the PHP of OPNsense has no sodium); the signature check is cached for
ten minutes. `cloud/server/licenselib.py` and `License.php` implement the same format.

## Limits

- The check is offline software on a machine the customer controls: someone with
  root on the firewall can patch the plugin. The license stops honest mistakes
  and casual copying, not a determined attacker.
- A trial is once per installation id; reinstalling the operating system changes
  the host id and allows another trial.

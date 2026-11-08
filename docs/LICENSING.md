# License module

The plugin needs a license key to run. Keys are made by the vendor and checked on the firewall with a public key, so a firewall can never create
keys for itself. The vendor-side tooling is a separate product and is not part of this repository.

## Key types

| Type | Length | Typical use |
|------|--------|-------------|
| Trial | 30 days | evaluation; a firewall can ask the vendor's server for one, once |
| Standard | 365 days | yearly subscription |
| Lifetime | never ends | one-off purchase |

A key may be tied to one firewall (its **installation id**) or work on any firewall. The installation id looks like `1234-ABCD-5678-EF01`; it is
derived from the firewall's host id (`kern.hostuuid`) and shown on **Layer 7 > License**. Two firewalls that were cloned from one disk image share
a host id: give each its own (`uuidgen > /etc/hostid`, then reboot) before issuing keys tied to them.

## On the firewall

**Layer 7 > License** shows the state, type, end date, installation id and the connection to the vendor's server. You can paste a key, start the
30-day trial, or remove the key.

Rules:

- A running license is replaced only by a key that runs **longer** (a renewal).
- A **lifetime** license cannot be replaced.
- A key tied to another firewall, a damaged key and an expired key are refused.
- A dated license stops if the clock is turned back by more than a day (the last time seen is kept with a MAC). The server's time fixes it at the
  next check-in.

Without a valid license (none, expired, withdrawn, wrong clock) the plugin is **locked**:

- its pages open the License page and its APIs answer HTTP 402,
- the engine, DNS filter, proxy, sign-in portal and pf rules are switched off (the same as unticking *Enabled*), downloads of lists stop,
- **traffic through the firewall is not touched**: the lock fails open, it never cuts the network.

Entering a valid key applies everything again within seconds. A cron job checks the state every 15 minutes (so an end date is noticed) and reports to
the server once an hour.

## Check-in

Once an hour (and on *Check in and update now*) the firewall reports its installation id, key, plugin version and host name to the server and learns
the state of its license: a key can be **withdrawn** (the firewall locks), **reinstated** (it unlocks) or **replaced** (installed by the firewall itself
if it runs longer). The check-in is optional: a firewall that cannot reach the server keeps working with the key it has until the key ends.

## Key format

22 bytes (version, type, issue day, length in days, 8 random key id bytes, 8 bytes binding) plus an Ed25519 signature (64 bytes) over `L7LIC1\0` and
those bytes, written as base32 in groups of five. Ed25519 is verified with the `openssl` command (the PHP of OPNsense has no sodium); the signature
check is cached for ten minutes. The vendor's public key is compiled into the plugin (`PUBKEY_B64` in `License.php`); a plugin built with a different
public key only accepts keys from that vendor.

## Limits

- The check is offline software on a machine the customer controls: someone with root on the firewall can patch the plugin. The license stops honest
  mistakes and casual copying, not a determined attacker.
- A trial is once per installation id; reinstalling the operating system changes the host id and allows another trial.

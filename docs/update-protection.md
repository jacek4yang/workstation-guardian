# Windows Update protection

## The mechanism

Local policy under `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`. This is the same
surface Group Policy writes and is the documented way to control update behaviour.

Guardian writes three values, and treats one of them as the primary protection:

| Value | Data | Role |
|---|---|---|
| `NoAutoUpdate` | `1` | **Primary.** Automatic updating is disabled by policy. |
| `NoAutoRebootWithLoggedOnUsers` | `1` | Defence in depth: no automatic restart while a user is logged on. |
| `AlwaysAutoRebootAtScheduledTime` | `0` | Defence in depth: no forced restart at a scheduled time. |

It additionally inspects and neutralizes local update **deadline** policies that could force a
restart despite the above (`SetAutoRestartDeadline`, `SetAutoRestartNotificationConfig`,
`SetUpdateNotificationLevel`).

A deadline policy is neutralized by being zero **or absent** — a value that does not exist cannot
force anything. Using absence as an acceptable state is not a shortcut: treating an absent value as
an unmet requirement made every stock Windows machine report `Degraded` forever, and made the
runtime write three zeros on every pass for no benefit.

## What Guardian does not do

None of the following, all of which are fragile, unsupported, or actively undone by Windows
servicing:

* disabling the `wuauserv` service;
* deleting Windows Update scheduled tasks;
* changing ACLs on system binaries;
* renaming system executables;
* repeatedly killing `MoUsoCoreWorker.exe` or `TrustedInstaller.exe`;
* patching Windows components;
* firewall-blocking Microsoft endpoints;
* looping on `AbortSystemShutdown`.

These approaches also damage the machine's security posture — leaving it unpatched — which is a cost
the operator never agreed to.

## Verification

Verification reads policy, compares it against what Guardian intends, writes only genuine
**differences**, and re-reads so the report describes the state *after* the pass.

The re-read matters for honesty: the report answers "are updates locked right now". Reporting the
pre-write observation would show `Degraded` for a whole verification interval after a successful
repair.

### Idle cost

On a conformant machine a verification pass performs **zero registry writes**. This is asserted by
test, because writing every few minutes forever would be a real defect on a machine that runs this
for months.

## Management detection

An organisation can override local policy, and Guardian must not claim a guarantee it cannot keep.
Management is detected from evidence that actually implies control:

* **Domain join** — read from `Tcpip\Parameters\Domain`, not from a Net API that can block on an
  unreachable domain controller.
* **MDM** — update policy actually delivered through the `PolicyManager` CSP, or the documented MDM
  push enrollment type (`EnrollmentType = 6`).

### Why the enrollment registry is not the signal

`HKLM\SOFTWARE\Microsoft\Enrollments` contains many entries on a **completely unmanaged** machine.
Measured on a stock Windows 11 workstation:

```text
EnrollmentState = 1 with EnrollmentType of 1, 2, 10, 11, 18, 28, 29, 30, 31, 32
ProviderID values of "Local Authority", "Cloud Authority", "Deploy Authority"
```

None of these means the machine is managed. They are the policy-authority declarations Windows
ships with. Treating any of them as enrollment produced a permanent false `Degraded`, which teaches
an operator to ignore the one warning that matters.

When a machine *is* externally managed, Guardian reports `Degraded`, names what is externally
controlled, and does not fight it.

## Tamper detection

If a Guardian-owned value is found changed:

1. the event is recorded in the journal and as an incident;
2. the value is restored (when `auto_restore` is enabled);
3. the tray is notified and the incident appears in the UI.

A mismatch that something keeps reintroducing raises **one** incident, not one per pass. Without
suppression, a persistent mismatch would generate an incident every couple of minutes and bury
everything else.

## Reading the status

```text
UPDATE PROTECTION

  Status              Protected
  Primary lock        NoAutoUpdate=1 is in effect
  Management          not externally managed

  Guardian-owned policy values:
    NoAutoUpdate                         OK           ...
    NoAutoRebootWithLoggedOnUsers        OK           ...
    AlwaysAutoRebootAtScheduledTime      OK           ...
```

`Protected` is shown only when every requirement is met, right now, with nothing external in the
way. Unreadable policy is `Unknown`. A failed write is `Unknown`, because values that look right
but could not be enforced are not protection.

## Uninstall

Uninstall restores **only the values Guardian recorded owning**.

Values that belonged to Group Policy or MDM are not in that list, so they are left exactly as they
are. Uninstall never reboots the machine. `--keep-policy` leaves update policy in place.

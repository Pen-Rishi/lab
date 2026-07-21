# Viewer Role Has Near-Owner Privileges — Only Non-Owner Role With Access to Dashboard, Entities, Bank Accounts, Billing, Calendar, Tasks, and Notifications

## Summary

The `viewer` role on manage.plane.com has near-owner-level access to the platform. On **8 critical endpoints** containing financial and administrative data, the viewer is the **only non-owner role with access** — all 6 other roles (full_access_manager, standard_manager, direct_reports_payer, payment_request_assistant, hr_coordinator, accountant) return HTTP 403. This was verified across all 7 non-owner roles by logging into each account and testing the same endpoints.

The viewer can access entity details (Federal EIN, state of incorporation, business address), bank account pages (Plaid integration), billing/invoice data, the company dashboard, calendar, tasks, and notifications. The entity page shows the same data fields as the owner (only the "Edit" and "Add person" buttons are hidden). On a payroll platform handling EINs and bank accounts, this is a critical authorization failure.

## Severity

**High** — CWE-863: Incorrect Authorization

## Affected Asset

`manage.plane.com` — role-based access control system

## Steps to Reproduce

### Step 1: Log in as a viewer

Log in with a user who has the `viewer` role: `maybeyouget27+viewer@gmail.com`

### Step 2: Access the entity details page

```
GET /0/entities/ent_6cjcTGp56PzXC7xu HTTP/2
Host: manage.plane.com
Cookie: [viewer session cookies]
```

**Viewer result: HTTP 200** (33,291 bytes) — Entity page with Federal EIN field, state of incorporation, business address, and bank account navigation.

**All other roles:**
- full_access_manager: **HTTP 403**
- standard_manager: **HTTP 404**
- direct_reports_payer: **HTTP 404**
- payment_request_assistant: **HTTP 404**
- hr_coordinator: **HTTP 404**
- accountant: **HTTP 404**

### Step 3: Access bank accounts page

```
GET /0/sources HTTP/2
Host: manage.plane.com
Cookie: [viewer session cookies]
```

**Viewer result: HTTP 200** — Bank account page with "Connect a bank account for [org] to fund payments, payroll, deposits, and Plane fees" and Plaid integration UI.

**All 6 other roles: HTTP 403**

### Step 4: Access billing page

```
GET /0/settings/invoices HTTP/2
Host: manage.plane.com
Cookie: [viewer session cookies]
```

**Viewer result: HTTP 200** — Plan & billing page with invoice data.

**All 6 other roles: HTTP 403**

### Step 5: Access the company dashboard

```
GET /0/home HTTP/2
Host: manage.plane.com
Cookie: [viewer session cookies]
```

**Viewer result: HTTP 200** (34,765 bytes) — Full company dashboard.

**All 6 other roles: HTTP 403**

## Complete 7-Role Access Control Matrix

Tested with 8 accounts (owner + 7 roles). Each cell is the HTTP status code.

### Critical: Viewer-only endpoints (all other roles blocked)

| Endpoint | Data Exposed | Owner | **Viewer** | FullMgr | StdMgr | PayMgr | PayRev | HR | Acct |
|----------|-------------|-------|--------|---------|--------|--------|--------|------|------|
| `/0/home` | Dashboard | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/entities/ent_*` | EIN, tax, address | 200 | **200** | 403 | 404 | 404 | 404 | 404 | 404 |
| `/0/entities` | Entity listing | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/sources` | Bank accounts, Plaid | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/settings/invoices` | Billing, invoices | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/calendar` | Company calendar | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/notifications` | Notifications | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |
| `/0/tasks` | Task management | 200 | **200** | 403 | 403 | 403 | 403 | 403 | 403 |

### Additional viewer access (some other roles also have access)

| Endpoint | Owner | Viewer | FullMgr | StdMgr | PayMgr | PayRev | HR | Acct |
|----------|-------|--------|---------|--------|--------|--------|------|------|
| `/0/people` | 200 | 200 | 200 | 200 | 200 | 403 | 200 | 403 |
| `/0/people/onboarding` | 200 | 200 | 200 | 200 | 200 | 403 | 200 | 403 |
| `/0/vendors` | 200 | 200 | 200 | 200 | 200 | 403 | 200 | 403 |
| `/0/departments` | 200 | 200 | 200 | 200 | 200 | 403 | 403 | 403 |
| `/0/compliance/contractors` | 200 | 200 | 200 | 200 | 200 | 403 | 403 | 403 |
| `/0/accounting/items` | 200 | 200 | 200 | 200 | 200 | 200 | 200 | 200 |

### Correctly restricted for viewer

| Endpoint | Viewer | Owner |
|----------|--------|-------|
| `/0/settings/users` | 403 | 200 |
| `/0/workspace` | 403 | 200 |

### Sidebar navigation comparison

The server-rendered sidebar confirms the privilege inversion:

| Role | Sidebar links |
|------|--------------|
| **Owner** | 12+ links (full access) |
| **Viewer** | **12 links** — Dashboard, Calendar, Tasks, Notifications, People, Onboarding, Departments, Entities, Bank accounts, Plan & billing, Profile |
| Full-access manager | 4 links — Departments, People, Onboarding, Profile |
| Standard manager | 4 links — Departments, People, Onboarding, Profile |
| Direct reports payer | 4 links (estimated) |
| Payment request assistant | 1-2 links |
| HR coordinator | 3-4 links |
| Accountant | 1 link — Profile |

The viewer has **3x more navigation** than any manager role and **12x more** than the accountant.

## Impact

1. **Systemic privilege inversion on a payroll platform**: The viewer — designed as the lowest-privilege, read-only role — is the **only non-owner role** that can access 8 critical endpoints. Every other role, including `full_access_manager`, is correctly blocked with HTTP 403.

2. **Financial data accessible to lowest-privilege role**:
   - **Federal EIN** (Employer Identification Number) — on the entity details page
   - **Bank account connection interface** with Plaid integration details
   - **Billing and invoice data** for the organization's subscription
   - **Entity details**: company name, legal name, state of incorporation, business address

3. **Viewer sees the same entity data as the owner**: Content comparison shows the only difference between the owner's and viewer's entity page is the absence of "Edit" and "Add person" buttons. All data fields are identical.

4. **Company verification task reveals business setup details**: The viewer's task page shows verification requirements including "Legal entity: Name, EIN, and registered address" and "Owners: Anyone with 25% ownership."

5. **1099-NEC compliance data**: The viewer can access the compliance/contractors page which references automated 1099-NEC filing.

## Proof of Concept Accounts

| Role | Email | Verified |
|------|-------|----------|
| Owner | rishyendram@connectsecure.com | Session active |
| Viewer | maybeyouget27+viewer@gmail.com | Session active |
| Full-access manager | maybeyouget27+fullmgr@gmail.com | Session active |
| Standard manager | maybeyouget27+stdmgr@gmail.com | Session active |
| Direct reports payer | maybeyouget27+paymgr@gmail.com | Session active |
| Payment request assistant | maybeyouget27+payrev@gmail.com | Session active |
| HR coordinator | maybeyouget27+hr@gmail.com | Session active |
| Accountant | maybeyouget27+acct@gmail.com | Session active |

All 8 accounts tested. Entity ID: `ent_6cjcTGp56PzXC7xu`. Organization ID: `1c550df4-9823-41b0-9227-95467db4c655`.

## Recommendation

1. The viewer role appears to inherit owner-level GET access by default, with only `/0/settings/users` and `/0/workspace` explicitly denied. Invert this to deny-by-default and grant only the specific pages a viewer should access.
2. Audit the Rails authorization layer for a catch-all policy on the viewer role that passes through instead of blocking.
3. The sidebar rendering logic also needs to be corrected — it currently renders 12 navigation links for the viewer, matching the owner.
4. Add integration tests that validate the full access matrix across all 7 roles for every endpoint.

## References

- [OWASP: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-863: Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

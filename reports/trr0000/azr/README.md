# Elevated Access Toggle (Self-Elevation to Azure Root Scope)

## Metadata

| Key          | Value                             |
|--------------|-----------------------------------|
| ID           | TRR0000                           |
| External IDs | [AZT402], [T1098.003]             |
| Tactics      | Privilege Escalation, Persistence |
| Platforms    | Azure                             |
| Contributors | John McGuinness                   |

### Scope Statement

A principal holding the Microsoft Entra ID Global Administrator
directory role invokes the Azure Resource Manager action
`Microsoft.Authorization/elevateAccess/action`, causing the platform to
create a User Access Administrator role assignment for that same
principal at Azure root scope `/`.

Direct self-assignment of an Azure role-based access control (Azure
RBAC) role through `Microsoft.Authorization/roleAssignments/write` is
not covered here. It is a separate technique rather than a second path
to the same place: it depends on an existing Azure RBAC write
permission rather than on an Entra directory role, and the caller
parameterizes it on scope, role, and target principal where the elevate
action accepts no parameter at all. It also cannot reach root scope `/`
without a prior elevation. Privileged Identity Management activation of
an eligible role is likewise a separate technique, because activation
converts an eligibility that already exists into an active assignment
for a bounded window; activation of Global Administrator is one way to
satisfy this technique's prerequisite rather than an instance of this
technique. What the caller does with the acquired root-scope authority
afterwards sits outside the boundary as well, since the success
condition of this technique is the existence of the assignment rather
than its use.

## Technique Overview

A principal holding the Microsoft Entra ID Global Administrator
directory role invokes a single Azure Resource Manager action that
grants that same principal the Azure RBAC role User Access
Administrator at root scope `/`, the scope above every management group
and subscription in the tenant. The action carries no request body and
no caller-selectable parameter, so the platform fixes the granted role,
the granted scope, and the recipient. Because Microsoft Entra ID and
Azure resources are secured by two independent authorization systems,
the action is the documented mechanism that carries a directory-plane
identity into the resource plane, and the assignment it creates
outlives the directory role that authorized its creation.

## Technical Background

### Two Authorization Planes in a Microsoft Entra Tenant

Microsoft Entra ID and Azure resources are secured by two independent
authorization systems. Entra directory roles govern directory objects
such as users, groups, applications, domains, and licensing. Azure RBAC
governs Azure resources through Azure Resource Manager. Microsoft
states the separation directly: Microsoft Entra role assignments do not
grant access to Azure resources, Azure role assignments do not grant
access to Microsoft Entra ID, and by default the Global Administrator
does not have access to Azure resources. A tenant can hold a Global
Administrator who cannot read a single virtual machine, and a
subscription Owner who cannot read a single user object.

`Microsoft.Authorization/elevateAccess/action` is the documented
platform mechanism that bridges the two systems, and no Azure RBAC
permission is a prerequisite for it. A principal holding Global
Administrator and no Azure role assignment at any scope, with no
subscription access, no management group access, and no resource
access, reaches the top of the Azure resource hierarchy in one call.
Microsoft documents elevation as a Global Administrator capability and
lists it under no other directory role. That combination is what makes
the action a crossing between planes rather than a broadening of
privilege inside a plane the principal already occupies.

### Azure Scopes and Root Scope

Azure RBAC scopes nest: resource, resource group, subscription, management
group, and above all of them root scope `/`. The tenant root management group
sits below `/`. Multiple sources, including Microsoft's own management groups
overview and its Defender for Cloud tenant-wide permissions article, describe
the resulting grant as landing on the tenant root management group; the
assignment the platform creates is scoped to `/`. The portal `Access control
(IAM)` blade refuses to delete an assignment scoped to `/`, directing the
operator back to the toggle instead.

Two platform facts confirm `/` as a special scope. Built-in role definitions
carry an `assignableScopes` value of `["/"]`, and custom role definitions cannot
set `assignableScopes` to `/` at all.

### The Elevate Access Action

The action is a single Azure Resource Manager request: a `POST` to
`/providers/Microsoft.Authorization/elevateAccess` at
`management.azure.com`, carrying an `api-version` query parameter, with
operation ID `GlobalAdministrator_ElevateAccess`, returning `200 OK`
and no response body.

The platform validates the `api-version` value and enumerates the
accepted set when a value outside it is supplied:
`2014-04-01-preview`, `2014-07-01-preview`, `2014-10-01-preview`,
`2015-05-01-preview`, `2015-06-01`, `2015-07-01`, `2016-07-01`,
`2017-05-01`, and `2018-01-01-preview`. An unrecognized value returns
`404` with an `InvalidResourceType` code, and an absent value returns
`400` with a `MissingApiVersionParameter` code. Microsoft's REST
reference defines the operation under `2015-07-01`, while the how-to
article states that `2016-07-01` or later is required; the endpoint
accepts both, and the platform enumerates seven further versions as
accepted, so the stated minimum does not correspond to platform
behavior.

The request carries no body and no URI parameter other than
`api-version`. The caller cannot name a target principal, cannot choose
the granted role, and cannot select the scope. Microsoft's
`Microsoft.Authorization` permission reference describes the action as
granting the caller User Access Administrator access at the tenant
scope, and the platform fixes all three attributes of the resulting
assignment: the principal is the caller and only the caller, the role
is User Access Administrator (role definition ID
`18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`), and the scope is `/`. That
role combines read access to every Azure resource type with the full
`Microsoft.Authorization/*` and `Microsoft.Support/*` action sets, and
carries no write action outside those two resource providers, as its
definition in [Azure Built-in Roles Privileged - Microsoft Learn]
records. The authorization set covers creating, modifying, and deleting
role assignments and role definitions. It covers deny assignments
lexically as well, though Microsoft states that deny assignments cannot
be created directly and are system protected.

The effect is per-user rather than tenant-wide. Microsoft states that
the setting is not a global property and applies only to the currently
signed-in user, so one principal's elevation grants nothing to any
other principal in the tenant.

### Invocation Surfaces

The portal exposes the action as a toggle named `Access management for
Azure resources` under the Microsoft Entra ID `Properties` blade. The
same action is reachable through raw Azure Resource Manager REST, the
Azure CLI generic REST command, and the Python, Go, JavaScript, and
.NET management SDKs. Every one of those surfaces resolves to the same
action string against the same endpoint.

Two surfaces that cover adjacent operations do not carry the elevation
itself. Azure PowerShell has no dedicated elevation cmdlet: Microsoft's
PowerShell guidance for the technique directs the reader to the portal
or the REST API, and the documented PowerShell surface covers listing
and removing the root-scope assignment. Microsoft Graph exposes no
equivalent surface at all. Graph exposes Entra directory role
assignments, whose scope is carried in a `directoryScopeId` value that
identifies a directory object, a different namespace from the Azure
RBAC scope `/`; Azure RBAC root scope is not reachable through Graph.

### Durability of the Resulting Assignment

The assignment the platform creates is an ordinary Azure RBAC role
assignment object with its own lifecycle, and it is the durable product
of the technique.

The assignment is not time-bound and does not expire. The
`RoleAssignment` resource schema defines no time-bounding property at
all, Microsoft's published sample of the resulting assignment object
carries no expiry field, and Microsoft's only lifecycle language on the
toggle is a recommendation to remove the access once the root-scope
changes are made.

Two consequences follow. Deactivating a Privileged Identity Management
eligible assignment of Global Administrator does not remove the
root-scope assignment; Microsoft states that deactivating the role
assignment does not change the `Access management for Azure resources`
toggle to `No`. Removing the Global Administrator directory role from
the identity outright does not remove the assignment either, a case
Microsoft's documentation does not address: a principal that no longer
holds the directory role holds its User Access Administrator assignment
at scope `/`, and that assignment appears in a listing at that scope.
The Azure RBAC object outlives the Entra directory role that authorized
its creation, which is why this technique carries the Persistence
tactic alongside Privilege Escalation.

The assignment also takes effect without any renewal of the caller's
authorization context. An operation authorized only by the new
assignment succeeds on the token already held at the moment of the
call, because Azure role-based access control assignments are evaluated
per request and are not carried as claims in the access token. The
access token for an elevated principal contains no role definition
identifier, no assignment identifier, and no role assignment claim.
Microsoft's portal procedure directs the operator to sign out and sign
back in, which is a portal session behavior rather than a condition of
the grant.

### Removal

There is no de-elevate action. Microsoft's `Microsoft.Authorization`
operation table contains `elevateAccess/action` and nothing resembling
an inverse. Removing the grant is an ordinary
`Microsoft.Authorization/roleAssignments/delete` against the assignment
at scope `/`. Of the two platform log sources described below,
only the Entra directory audit log gives the removal a dedicated
activity name.

### Telemetry

Microsoft states that elevate access log entries appear in both the
Microsoft Entra directory audit logs and the Azure activity logs. The
two records carry different strings for the same operation.

The Entra directory audit record lands in the `AuditLogs` table with a
`Category` of `AzureRBACRoleManagementElevateAccess`. The elevation
carries an `ActivityDisplayName` of `User has elevated their access to
User Access Administrator for their Azure Resources`. The removal
carries an `ActivityDisplayName` of `The role assignment of User Access
Administrator has been removed from the user`.

The Azure Activity Log record is a Directory Activity entry. Its
operation display name is `Assigns the caller to User Access
Administrator role`, its `authorization.action` value is
`Microsoft.Authorization/elevateAccess/action`, its
`authorization.scope` value is `/providers/Microsoft.Authorization`,
its `category` value is `Administrative`, and its `subscriptionId`
value is empty. That display name is the `localizedValue` of the
record's `operationName` field, whose `value` is the action string
itself.

The two display strings do not cross over. `Assigns the caller to User
Access Administrator role` is an Azure Activity Log `operationName`
value and is not an `ActivityDisplayName` value in the Entra directory
audit log, where the elevation instead carries the string given above.
A filter applying the Activity Log string to the `ActivityDisplayName`
column of `AuditLogs` matches no rows. The sample query published with
[Azure Threat Research Matrix AZT402] makes that substitution.

One invocation produces two Azure Activity Log records, a `Started`
record and a `Succeeded` record sharing an operation identifier, and
one Entra directory audit record, stamped at the same moment as the
`Succeeded` record. Repeat invocation by an already elevated principal
produces a further full set of records in both sources while leaving
the existing assignment in place, updating only its `updatedOn` value.

Availability constraints attach to both records. The Azure Activity Log
copy is a tenant-level Directory Activity record with no
diagnostic-setting export path: Microsoft documents activity log
diagnostic settings at subscription and management group scope,
documents the `AzureActivity` table as carrying subscription-level and
management-group-level events, and retrieves tenant-level events
through a separate REST API whose path carries no subscription. Two
independent vendor analyses state that Directory Activity records have
no diagnostic export option. Reading the tenant-level log requires an
Azure role assignment at scope `/`, and Microsoft states that access to
tenant-level activity logs requires having used elevate access at least
once. The Entra directory audit copy is flagged preview: Microsoft
carries an Important banner stating that elevate access log entries in
the Entra directory audit logs are in preview. Microsoft's Azure RBAC
changelog dates that preview to January 2025.

A third source exists outside the two platform logs. Microsoft Defender
for Resource Manager publishes an alert named
`ARM_AnomalousElevateAccess`, with the display name `Suspicious elevate
access operation`, carrying a severity of `Medium` and mapped to the
Privilege Escalation tactic, which draws on Defender's internal log
sources and the Azure Activity log. That plan is a paid
per-subscription offering, and Microsoft's Azure Resource Manager
security baseline records that it is not enabled by default.

A fourth surface carries the raw operation string itself. The Microsoft
Defender XDR `CloudAuditEvents` advanced hunting table records Azure
Resource Manager control-plane events, holding the operation string in
its `OperationName` column and identifying the origin in `DataSource`.
Microsoft's own Storm-0501 hunting guidance queries that table for
`Microsoft.Authorization/elevateAccess/action`. The table is available
in the Defender portal and as a Log Analytics table, and it is
populated through Defender for Cloud onboarding.

### Benign Use

Microsoft documents four legitimate reasons for elevating: regaining
access to a subscription or management group after access is lost,
granting a user access, seeing all subscriptions in an organization,
and allowing an automation application tenant-wide access. The
recurring case is an orphaned subscription whose last Owner has left
the organization.

One benign path produces the full record set without a deliberate
invocation. Microsoft Defender for Cloud's tenant-wide visibility
feature performs the whole cycle automatically: assigning yourself
tenant-level permissions temporarily elevates the user's permissions,
uses those permissions to create the requested Azure RBAC role
assignment on the tenant root management group, and then removes the
elevated permissions. A Global Administrator who uses that feature
produces an elevation record and a removal record without knowing that
`Microsoft.Authorization/elevateAccess/action` was invoked at all.

Azure Lighthouse documents a second cycle, performed by hand. The
tenant-level activity log that records delegation changes requires a
role assignment at scope `/`, so Microsoft's procedure has a Global
Administrator elevate, assign Monitoring Reader at root scope,
preferably to a service principal, and then remove the elevation.
Microsoft notes that enterprises managing multiple tenants use the same
process.

### Real-World Usage

Public reporting that names this action is thin. Microsoft's own
Storm-0501 reporting describes the actor taking over a synced non-human
identity that held Global Administrator without multifactor
authentication (resetting its on-premises password, then registering an
actor-controlled multifactor method) and then invoking
`Microsoft.Authorization/elevateAccess/action` by name. The
[MITRE ATT&CK Scattered Spider Group] entry records the assignment of
user access admin roles to gain `Tenant Root Group` management
permissions in Azure, phrasing that names neither the action nor root
scope `/`, and that uses the tenant root management group wording
distinguished from `/` in [Azure Scopes and Root Scope].

## Procedures

| ID            | Title                              | Tactic                            |
|---------------|------------------------------------|-----------------------------------|
| TRR0000.AZR.A | Self-Elevation to Azure Root Scope | Privilege Escalation, Persistence |

### Procedure A: Self-Elevation to Azure Root Scope (TRR0000.AZR.A)

This procedure crosses the boundary between the two authorization
planes described in [Two Authorization Planes in a Microsoft Entra
Tenant], and that crossing is what distinguishes it from every adjacent
mechanism.

There is one procedure in this TRR because the operation exposes
nothing to vary. The request carries no body and no parameter other
than `api-version`, and the platform fixes the granted role, the
granted scope, and the recipient, so there is no surface on which
execution paths can diverge. The portal toggle, the Azure CLI generic
REST command, raw Azure Resource Manager REST, and the management SDKs
each emit the same action string against the same endpoint and produce
the same records, which makes them instances of this one path rather
than separate paths. Microsoft's Azure China rendering of the
capability is identical apart from the `management.chinacloudapi.cn`
hostname, and a hostname is not an essential operation, so that
rendering is an instance of this path as well. Invocation by a workload
identity holding the directory role is an instance of the same path for
the same reason: the credential flow that produced the token changes
which sign-in record exists upstream, not which operations the
technique performs.

One candidate path is closed by the platform rather than by a scoping
decision. A custom Azure role carrying the elevate action could not be
assigned where the action means anything, because custom role
definitions cannot set `assignableScopes` to `/`, so the action cannot
be delegated at root scope and no custom-role path reaches the
`Elevate Access to Root Scope` operation in the model. Microsoft Graph
likewise exposes no equivalent surface, so no Graph-mediated path
reaches that operation either.

Two prerequisites feed the single pipeline operation. `Hold Global
Administrator Role` is styled gray in the diagram to mark it as an
external prerequisite. The acquisition of that directory role is
observable in the tenant, and whatever produced it leaves its own
records, but the acquisition belongs to the upstream technique that
performed it and sits outside this TRR's boundary. Within this
technique's boundary the directory role is state the caller already
holds rather than an operation the caller performs, so that node
carries no telemetry label.

The directory role reaches Azure Resource Manager as a claim rather
than as a lookup. The role template identifier
`62e90394-69f5-4237-9190-012177145e10` is carried in the `wids` claim
of the access token, and the platform authorizes the request from the
presented token rather than from the directory state at the time of the
request. A token issued while the role was held continues to satisfy
the check after the role assignment is removed, for the remaining
lifetime of that token, and a token issued after the removal does not.
The Azure role-based access control assignment the technique creates
follows a different model, described in
[Durability of the Resulting Assignment]: it is an independent object
and survives removal of the directory role outright.

`Obtain ARM Token` is the second prerequisite, because `elevateAccess`
is an Azure Resource Manager endpoint and the caller presents an access
token whose audience is Azure Resource Manager at
`management.azure.com`. The sign-in entry carries a
`ResourceDisplayName` of `Azure Resource Manager`, which is the value
Microsoft filters on in its own published sign-in queries for that
resource, and a `ResourceIdentity` of
`797f4846-ba00-4fd7-ba43-dac1f8f63013`, which is the Azure Resource
Manager application identifier.

Three columns in the sign-in tables carry resource-shaped values and
only one of them identifies the sign-in target. `ResourceIdentity` holds the
application identifier, which is the same value in every tenant.
`ResourceServicePrincipalId` holds the object identifier of the Azure
Resource Manager service principal within the local tenant, which
differs from tenant to tenant. `ResourceId` is the Azure Monitor
diagnostic source column, carrying
`/tenants/<tenant>/providers/Microsoft.aadiam` on every row regardless
of which resource was signed in to. The schema also differs across the
two user tables: `SigninLogs` publishes `ResourceId` while
`AADNonInteractiveUserSignInLogs` does not, so a projection spanning
both tables that names `ResourceId` fails.

The table the entry lands in is determined by the credential flow rather
than by the technique. An interactive user sign-in produces
Entra SigninLogs (Azure Resource Manager) telemetry. A token obtained
silently from an existing session, which covers both the refresh-token
exchange behind a command-line client and the portal's own silent
acquisition, produces
Entra AADNonInteractiveUserSignInLogs (Azure Resource Manager)
telemetry. A workload identity holding the Global Administrator
directory role can also invoke the action: a service principal
presenting a client credentials token for
`https://management.azure.com/.default` receives the same `200` and the
platform creates the same assignment for it, with a `principalType` of
`ServicePrincipal`. That acquisition produces
Entra AADServicePrincipalSignInLogs (Azure Resource Manager) telemetry,
carrying the same resource display name and the same application
identifier as the user flows, and identifying the caller by service
principal object ID. Repeated acquisitions by one service principal are
presented as a single aggregated entry rather than one entry each.

A managed identity holding the same directory role can invoke the
action as well. A managed identity acquiring an Azure Resource Manager
token from the instance metadata endpoint receives the same `200`, and
the platform creates an assignment for it with a `principalType` of
`ServicePrincipal`, because a managed identity is a service principal
in Microsoft Entra ID. That acquisition produces
Entra AADManagedIdentitySignInLogs (Azure Resource Manager) telemetry,
again carrying the same resource display name and application
identifier.

The four sign-in tables therefore correspond one to one with the four
credential flows that can reach the elevate action, and each flow lands
in exactly one of them. The sign-in entry records token issuance rather
than the invocation, so a token already held when the action is invoked
produces no sign-in entry at that moment.

The records that identify the caller differ by principal type. In
Azure Activity Log Directory Activity
(Microsoft.Authorization/elevateAccess/action) telemetry the `caller`
field carries a user principal name for a user and a bare object
identifier for a service principal. In
Entra AuditLogs (User has elevated their access to User Access
Administrator for their Azure Resources) telemetry the
`ActivityDisplayName` is the same string for every caller type, and the
caller is distinguished only by which branch of `InitiatedBy` is
populated: `user` for a user, and `app.servicePrincipalId` for a
workload identity, where `app.appId` and `app.displayName` are both
empty.

Three caller types produce two record shapes. A user is distinguishable
from a workload identity, but an application registration's service
principal and a managed identity are not distinguishable from one
another in either source: both populate the same fields with the same
shape, and both produce an assignment whose `principalType` is
`ServicePrincipal`. That distinction does exist upstream, in the
prerequisite: the two land in different sign-in tables. It is not
carried forward into the record of the operation itself.

The pipeline operation is `Elevate Access to Root Scope`. It produces
Entra AuditLogs (User has elevated their access to User Access
Administrator for their Azure Resources) telemetry carrying a
`Category` of `AzureRBACRoleManagementElevateAccess` and a
`LoggedByService` of `Azure RBAC (Elevated Access)`, and
Azure Activity Log Directory Activity
(Microsoft.Authorization/elevateAccess/action) telemetry carrying an
`authorization.scope` of `/providers/Microsoft.Authorization`, a
`category` of `Administrative`, and an empty `subscriptionId`. The
record count each source writes per invocation is given in [Telemetry].
Where Defender for Cloud is onboarded, the same operation string is
recorded as Microsoft Defender XDR CloudAuditEvents
(Microsoft.Authorization/elevateAccess/action) telemetry.
The role assignment the platform creates in the same
transaction is the outcome of this operation rather than a separate
operation, because no caller step sits between the request and the
assignment. The assignment's role definition ID
`18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` and its scope `/` are recorded
as properties of this operation in the model; the principal is always
the caller, which is a property of the action rather than a value that
varies from one assignment record to another. The assignment's
lifecycle is described in
[Durability of the Resulting Assignment].

#### Detection Data Model

![TRR0000.AZR.A DDM](ddms/trr0000_azr_a.png)

The rendered diagram carries a single pipeline operation. Red arrows
run from both prerequisite nodes into `Elevate Access to Root Scope`,
marking both as on the active path: the technique proceeds only with
the directory role and with a token whose audience is Azure Resource
Manager. `Hold Global Administrator Role` is the gray external
prerequisite described above and carries no telemetry label. `Obtain
ARM Token` is a black prerequisite carrying four sign-in tables, one per
credential flow: interactive user, non-interactive user, application
service principal, and managed identity. Its `DelegatedScope` and
`ApplicationScope` properties record the two scope values, one per
credential family (delegated and application), without the resource
hostname that the token carries separately in its audience claim.

`Elevate Access to Root Scope` carries the fixed attributes of the
assignment the platform creates, including a `PrincipalType` of
`User | ServicePrincipal`. Those are the only two values the assignment
can carry, and a managed identity produces the second of them.

## Available Emulation Tests

| ID            | Link                                              |
|---------------|---------------------------------------------------|
| TRR0000.AZR.A | [Stratus Red Team Root User Access Administrator] |

## References

- [Azure Threat Research Matrix AZT402]
- [MITRE ATT&CK T1098.003]
- [MITRE ATT&CK Scattered Spider Group]
- [Elevate Access to Manage Azure Subscriptions - Microsoft Learn]
- [Global Administrator Elevate Access REST API - Microsoft Learn]
- [Azure Permissions for Management and Governance - Microsoft Learn]
- [Azure Roles and Microsoft Entra Roles - Microsoft Learn]
- [Azure RBAC Scope Overview - Microsoft Learn]
- [Azure Built-in Roles Privileged - Microsoft Learn]
- [Azure Deny Assignments - Microsoft Learn]
- [Management Groups Overview - Microsoft Learn]
- [Azure Custom Role Limits - Microsoft Learn]
- [Azure Role Definition AssignableScopes - Microsoft Learn]
- [Microsoft Entra Built-in Roles - Microsoft Learn]
- [Roles Across Microsoft Services - Microsoft Learn]
- [Microsoft Graph unifiedRoleAssignment Resource - Microsoft Learn]
- [Microsoft Entra Audit Activity Reference - Microsoft Learn]
- [AuditLogs Table Schema - Microsoft Learn]
- [SigninLogs Table Schema - Microsoft Learn]
- [AADNonInteractiveUserSignInLogs Table Schema - Microsoft Learn]
- [AADServicePrincipalSignInLogs Table Schema - Microsoft Learn]
- [AADManagedIdentitySignInLogs Table Schema - Microsoft Learn]
- [Access Token Claims Reference - Microsoft Learn]
- [Token Protection Deployment Guide for Web Apps - Microsoft Learn]
- [Azure Monitor Activity Log - Microsoft Learn]
- [Defender for Cloud Resource Manager Alerts - Microsoft Learn]
- [Defender for Resource Manager Alert Sources - Microsoft Learn]
- [CloudAuditEvents Table Schema - Microsoft Learn]
- [Azure RBAC What's New Changelog - Microsoft Learn]
- [Azure Resource Manager Security Baseline - Microsoft Learn]
- [Defender for Cloud Tenant-Wide Permissions Management - Microsoft Learn]
- [Azure Lighthouse Monitor Delegation Changes - Microsoft Learn]
- [Elevate Access Global Admin - Azure China Documentation]
- [Storm-0501 Evolving Techniques - Microsoft Security Blog]
- [Azure Apex Permissions Elevate Access - Permiso]
- [Microsoft Entra Elevated Access Logs - Chance of Security]
- [Stratus Red Team Root User Access Administrator]
- [Atomic Red Team T1098.003 Atomics]

[Two Authorization Planes in a Microsoft Entra Tenant]: #two-authorization-planes-in-a-microsoft-entra-tenant
[Azure Scopes and Root Scope]: #azure-scopes-and-root-scope
[Durability of the Resulting Assignment]: #durability-of-the-resulting-assignment
[Telemetry]: #telemetry
[AZT402]: https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
[T1098.003]: https://attack.mitre.org/techniques/T1098/003/
[Azure Threat Research Matrix AZT402]: https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT402/AZT402/
[MITRE ATT&CK T1098.003]: https://attack.mitre.org/techniques/T1098/003/
[MITRE ATT&CK Scattered Spider Group]: https://attack.mitre.org/groups/G1015/
[Elevate Access to Manage Azure Subscriptions - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
[Global Administrator Elevate Access REST API - Microsoft Learn]: https://learn.microsoft.com/en-us/rest/api/authorization/global-administrator/elevate-access
[Azure Permissions for Management and Governance - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/permissions/management-and-governance#microsoftauthorization
[Azure Roles and Microsoft Entra Roles - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/rbac-and-directory-admin-roles
[Azure RBAC Scope Overview - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/scope-overview
[Azure Built-in Roles Privileged - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/privileged#user-access-administrator
[Azure Deny Assignments - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/deny-assignments
[Management Groups Overview - Microsoft Learn]: https://learn.microsoft.com/azure/governance/management-groups/overview
[Azure Custom Role Limits - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/custom-roles#custom-role-limits
[Azure Role Definition AssignableScopes - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/role-definitions#assignablescopes
[Microsoft Entra Built-in Roles - Microsoft Learn]: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#global-administrator
[Roles Across Microsoft Services - Microsoft Learn]: https://learn.microsoft.com/entra/identity/role-based-access-control/m365-workload-docs
[Microsoft Graph unifiedRoleAssignment Resource - Microsoft Learn]: https://learn.microsoft.com/graph/api/resources/unifiedroleassignment
[Microsoft Entra Audit Activity Reference - Microsoft Learn]: https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities#azure-rbac-elevated-access
[AuditLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/auditlogs
[SigninLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs
[AADNonInteractiveUserSignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
[AADServicePrincipalSignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
[AADManagedIdentitySignInLogs Table Schema - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs
[Access Token Claims Reference - Microsoft Learn]: https://learn.microsoft.com/entra/identity-platform/access-token-claims-reference
[Token Protection Deployment Guide for Web Apps - Microsoft Learn]: https://learn.microsoft.com/entra/identity/conditional-access/deployment-guide-token-protection-web-apps
[Azure Monitor Activity Log - Microsoft Learn]: https://learn.microsoft.com/azure/azure-monitor/platform/activity-log
[Defender for Cloud Resource Manager Alerts - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/alerts-resource-manager
[Defender for Resource Manager Alert Sources - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-resource-manager-usage
[CloudAuditEvents Table Schema - Microsoft Learn]: https://learn.microsoft.com/defender-xdr/advanced-hunting-cloudauditevents-table
[Azure RBAC What's New Changelog - Microsoft Learn]: https://learn.microsoft.com/azure/role-based-access-control/whats-new
[Azure Resource Manager Security Baseline - Microsoft Learn]: https://learn.microsoft.com/security/benchmark/azure/baselines/azure-resource-manager-security-baseline
[Defender for Cloud Tenant-Wide Permissions Management - Microsoft Learn]: https://learn.microsoft.com/azure/defender-for-cloud/tenant-wide-permissions-management
[Azure Lighthouse Monitor Delegation Changes - Microsoft Learn]: https://learn.microsoft.com/azure/lighthouse/how-to/monitor-delegation-changes
[Elevate Access Global Admin - Azure China Documentation]: https://docs.azure.cn/en-us/role-based-access-control/elevate-access-global-admin
[Storm-0501 Evolving Techniques - Microsoft Security Blog]: https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
[Azure Apex Permissions Elevate Access - Permiso]: https://permiso.io/blog/azures-apex-permissions-elevate-access-the-logs-security-teams-overlook
[Microsoft Entra Elevated Access Logs - Chance of Security]: https://www.chanceofsecurity.com/post/microsoft-entra-elevated-access-logs-better-security-better-insights
[Stratus Red Team Root User Access Administrator]: https://stratus-red-team.cloud/attack-techniques/azure/azure.privilege-escalation.root-user-access-administrator/
[Atomic Red Team T1098.003 Atomics]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.yaml

# Steal Application Access Token (Microsoft Entra ID)

## Metadata

| Key          | Value                                                  |
|--------------|--------------------------------------------------------|
| ID           | TRR0000                                                |
| External IDs | [AZT203], [AZT601], [T1528]                            |
| Tactics      | Credential Access                                      |
| Platforms    | Azure                                                  |
| Contributors | John McGuinness                                        |

### Scope Statement

This TRR covers OAuth access-token acquisition on Microsoft Entra ID where an
adversary causes a legitimate Entra ID OAuth flow to issue tokens to
attacker-controlled infrastructure, or obtains a token for a managed identity or
federated workload identity on a compromised Azure compute or AKS resource.

The pipeline ends at the adversary's first receipt of the access or refresh
token; later use of the token is [T1550.001]. This TRR treats theft of an
application secret or certificate from disk, a repository, or a key vault as
[T1552] and a read of a client's on-disk token cache as [T1552.001]. It treats
issuance with a stolen secret or certificate on a legitimately consented
principal as [T1078.004]; authorization-code phishing against a Microsoft
first-party `client_id` is [TRR0034]. Azure Arc-enabled servers, Logic Apps
workflows, federated identity credentials trusting issuers outside Azure
compute, and authentication transfer are not modeled.

## Technique Overview

An adversary obtains a Microsoft Entra ID access token or refresh token issued
for a user, service principal, managed identity, or federated workload identity.
Entra ID issues bearer tokens, which any party in possession can use without
demonstrating possession of a cryptographic key. Because the authentication
requirements were met when the token was issued, a replayed token grants the
adversary access to organizational resources even where the user satisfied
multifactor authentication.

## Technical Background

### Microsoft Identity Platform Endpoints

Example v2.0 authorization and token endpoints are
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` and
`https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.[^1] Interactive
user flows obtain authorization at `/authorize` and redeem at `/token`. The
device code flow posts to `/oauth2/v2.0/devicecode` and then polls `/token`.[^2]
Client credentials and federated-credential exchange also post to
`/oauth2/v2.0/token`.[^3] The documented managed identity token requests go to
the IMDS address or the URL in `IDENTITY_ENDPOINT`, as described in [The
Instance Metadata Service]. AKS workload identity exchanges a projected
Kubernetes service account token at the Entra token endpoint rather than through
IMDS.[^4]

### Device Authorization Grant Internals

In the device authorization grant the device requesting the authorization is not
the same as the device from which the user grants access.[^5] Entra ID has no
reliable way to verify that the person who enters the code is signing in from
the device that generated it.[^6] The client posts `client_id` and `scope` to
`/oauth2/v2.0/devicecode` and receives a `device_code`, a `user_code` for the
user to enter at the verification URI, and the code's lifetime and polling
interval.[^2] An example verification URI is
`https://microsoft.com/devicelogin`.[^7] While the user authenticates there, the
client polls `/oauth2/v2.0/token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` and the `device_code`;
once the user signs in, it obtains access tokens and, if `offline_access` was in
the original `scope`, a refresh token.[^2] The flow is available only for public
client applications,[^7] and since June 2021 it includes a prompt that validates
the user is signing into the app they expect.[^8]

### Authorization Code Flow Internals

The authorization code flow is a two-leg exchange.[^9] An `/authorize` request
carrying `client_id`, `scope`, and a registered `redirect_uri` returns a code to
that URI once the user authenticates and consents; a `/token` request with
`grant_type=authorization_code`, the code, and the same `redirect_uri` redeems
it. Confidential web apps authenticate the redemption with a `client_secret` or
a `client_assertion` JWT signed with a registered certificate. The response
carries an access token and, only if `offline_access` was requested, a refresh
token. A code may be used to redeem an access token only once.[^7]

### Client Credentials and Federated Credential Exchange

Service principal token issuance is a POST to `/oauth2/v2.0/token` with
`grant_type=client_credentials`.[^3] The client authenticates with a shared
secret or with a `client_assertion` JWT. It creates and signs the assertion
itself with the certificate registered for it, or it gets the assertion from
another identity provider, such as Kubernetes; the specifics of that JWT are
registered on the application as a federated identity credential. The assertion
cases set `client_assertion_type` to
`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. The `/.default` scope
value tells the platform to issue a token for the direct application permissions
configured for the resource, and refresh tokens are never granted with this
flow. Permissions are granted directly to the application by an administrator,
and no user is involved. AKS workload identity presents the kubelet-projected
service account JWT as the `client_assertion`.[^4] The federated identity
credential's `issuer`, `subject`, and `audience` values must case-sensitively
match the corresponding claims in the token;[^10] when the checks pass, the
platform issues an access token to the external workload.

### The Instance Metadata Service

The Instance Metadata Service (IMDS) is a REST API at the non-routable address
`169.254.169.254`, accessible only from within a running virtual machine
instance,[^11] and its managed identity token endpoint is
`http://169.254.169.254/metadata/identity/oauth2/token`.[^12] The security
boundary of a managed identity is the resource where it is used: all code and
scripts running on a virtual machine can request and retrieve tokens for any
managed identity available on it.[^12] A request must carry the header
`Metadata: true`, a mitigation against server-side request forgery. Its
`resource` query parameter names the target resource's App ID URI, which also
appears in the issued token's `aud` claim. The token is based on the managed
identity's service principal[^12] and represents the application that accesses
the resource.[^13] The managed identities subsystem caches tokens, so a call to
Entra ID results only when no token is in the cache or the cached token is
expired.[^12]

App Service, Azure Functions, and Container Apps expose an internally accessible
token endpoint whose URL is in `IDENTITY_ENDPOINT`. The caller sends the
platform-rotated `IDENTITY_HEADER` value as the `X-IDENTITY-HEADER` header on an
HTTP GET to that URL.[^13][^14][^15] Azure Automation's runbook samples send the
same header to the URL in `IDENTITY_ENDPOINT`.[^16] Service Fabric exposes an
HTTPS `localhost` token service whose URL is also in `IDENTITY_ENDPOINT` and
which takes a `Secret` header.[^17] The Container Instances sample token request
goes to the IMDS address with the `Metadata` header, or, for Windows container
instances, to `IDENTITY_ENDPOINT` with `IDENTITY_HEADER`.[^18] In an AKS cluster
the IMDS endpoint is reachable from all pods by default; when IMDS restriction
is enabled, pods that are not on the host network cannot acquire managed
identity tokens from it.[^19]

### Access Tokens

An Entra ID access token is a signed JSON web token[^20] whose claims are
defined in the access token claims reference,[^21] and a standard OAuth2 token
contains no certificate binding information.[^22] An access token receives a
random default lifetime between 60 and 90 minutes, or up to 28 hours when both
the client and the resource support Continuous Access Evaluation;[^23][^24] a
managed identity token is valid for 24 hours.[^25] A refresh token's Max
Inactive Time is 90 days and its Max Age is until-revoked;[^23] one sent to a
redirect URI registered as `spa` expires after 24 hours.[^9] The user has 15
minutes from the device authorization request to sign in, the default
`expires_in` of a device code.[^2]

### Conditional Access and Device Code Flow

The Conditional Access authentication flows condition explicitly targets device
code flow.[^26] Protocol tracking state is sustained through subsequent
refreshes, so a session that began with device code flow can remain subject to
authentication flows policies. A tenant with security defaults enabled blocks
authentication requests that use device code flow, and starting July 1, 2026,
all new Microsoft Entra tenants block it as part of security defaults.[^27] The
require-managed-device grant control and device state conditions are not
supported with device code flow, because the device performing authentication
cannot provide its device state to the device that is providing a code.[^28]

### OAuth Consent Framework

Delegated permissions let an application act on a user's behalf and appear in
the `scp` claim; application permissions, also known as app roles, are used in
the app-only scenario without a signed-in user and are carried in the `roles`
claim.[^29][^30] Users can consent to delegated permissions for their own data
and administrators for all users;[^29] app-only permissions always require a
tenant administrator's consent.[^31] For Microsoft Graph the result of consent
is an `OAuth2PermissionGrant` for delegated permissions or an
`appRoleAssignment` for application permissions,[^29] and an
`OAuth2PermissionGrant` carries `consentType` `Principal` (one user) or
`AllPrincipals` (all users, grantable by an administrator).[^32] Application
permissions can be granted through a consent experience.[^33]

Tenant user-consent settings include disabling user consent; allowing consent
only to applications from verified publishers or the organization, and only for
permissions the administrator selects; and allowing consent to any application
for any permission that does not require admin consent.[^34] Risk-based step-up
consent is enabled by default and changes behavior only when user consent is
enabled; with it, users cannot consent to most newly registered multitenant apps
that are not publisher verified.[^35][^36] The Microsoft managed consent policy,
the default for a new tenant, lets end users consent to any user-consentable
delegated permission except a Microsoft-maintained list of Microsoft Graph and
Exchange Online scopes.[^37]

Granting tenant-wide admin consent requires signing in as a user authorized to
consent on behalf of the organization.[^38] Privileged Role Administrator
qualifies for any permission on any API. Cloud Application Administrator, AI
Administrator, and Application Administrator qualify for any permission except
Microsoft Graph app roles.[^38][^39] A custom directory role that includes the
permission to grant permissions to applications also qualifies.[^38] The admin
consent endpoint `https://login.microsoftonline.com/{tenant}/v2.0/adminconsent`
requires a tenant administrator to sign in to complete the request.[^40]
Application permissions are requested through the `/.default` scope value, and
the documented success redirect carries `admin_consent=True`, `tenant`, `scope`,
and `state`.

### Telemetry Surfaces

Entra ID sign-in logs have four types: interactive user, non-interactive user,
service principal, and managed identity sign-ins.[^41] In an interactive sign-in
the user provides an authentication factor to Entra ID.[^42] A non-interactive
sign-in is done on behalf of a user by a client app or OS component without the
user providing a factor. Examples are a client app using a refresh token to get
an access token and a client using an authorization code to get an access token
and refresh token.[^43] A service principal sign-in involves no user: the app
provides its own credential, such as a certificate or app secret, and an
application using a client secret in the client credentials flow is an
example.[^44] Managed identity sign-ins are performed by resources whose secrets
Azure manages.[^45] In a Log Analytics workspace the four types are the
`SigninLogs`, `AADNonInteractiveUserSignInLogs`,
`AADServicePrincipalSignInLogs`, and `AADManagedIdentitySignInLogs`
tables.[^46][^47][^48][^49][^50]

`AuthenticationProtocol` lists the protocol type or grant type used in the
authentication, and `deviceCode` is among its values.[^46]
`OriginalTransferMethod` carries the transfer method used to initiate a session
throughout all subsequent requests;[^46] the Graph `originalTransferMethod`
value for a session begun with device code flow is `deviceCodeFlow`.[^51]

`AuditLogs` is the Microsoft Entra audit log, which captures changes to
applications, groups, users, and licenses, with the activity in
`ActivityDisplayName`.[^47][^52] The audit log's Core Directory activities in
category `ApplicationManagement` include `Add app role assignment to service
principal`, `Add delegated permission grant`, `Add service principal`, and
`Consent to application`.[^53] `Consent to application` corresponds to a user
granting consent, `Add delegated permission grant` to granting delegated access,
and `Add app role assignment to service principal` to granting app-only
access.[^54]

On the host, an outbound connection from the resource is observable as a Linux
auditd `SYSCALL` record under a syscall rule that names `connect`.[^55][^56] It
is also observable as Sysmon event ID 3 (NetworkConnect), which logs TCP and UDP
connections linked to a process, is disabled by default, and is defined in the
shared event manifest for Windows and Linux.[^57][^58] A file read in a pod is
observable as an auditd record under a syscall rule with `-F path`.[^55] An
audit event contains a `PATH` record for every path passed to the system
call,[^56] and since glibc 2.26 the `open()` wrapper issues the `openat()`
system call.[^59] `AKSAudit` contains all Kubernetes API server audit logs,
requires diagnostic settings, and carries the request's `Verb` and
`ObjectRef`.[^60][^61][^62] In the Kubernetes authorization model an HTTP `POST`
maps to the `create` verb.[^63]

## Procedures

| ID | Title | Tactic |
|---|---|---|
| TRR0000.AZR.A | Device Code Phishing | Credential Access |
| TRR0000.AZR.B | Multi-Tenant Illicit Consent Grant | Credential Access |
| TRR0000.AZR.C | Managed Identity Token Retrieval | Credential Access |
| TRR0000.AZR.D | AKS Workload Identity Token Theft | Credential Access |

### Procedure A: Device Code Phishing (TRR0000.AZR.A)

This procedure covers the device authorization grant initiated on a device in
the adversary's possession, with the victim granting access from another device;
the request and response shapes are stated in [Device Authorization Grant
Internals]. The adversary generates a legitimate device code request at
`/oauth2/v2.0/devicecode` and tricks the victim into entering the `user_code` at
a legitimate Microsoft sign-in page.[^64] The victim's authentication at the
verification page authenticates the adversary's session,[^65] and the
adversary's client, polling `/oauth2/v2.0/token` with the device-code grant
type, receives the resulting access and refresh tokens[^64] through a back
channel.[^7]

In device code flow the user signs in interactively.[^7] The victim's
device-code authentication is an `Entra SigninLogs (Interactive sign-in)` row
with `AuthenticationProtocol` = `deviceCode`. That placement follows from the
sign-in being interactive, from the interactive sign-in definition and the
`deviceCode` value in [Telemetry Surfaces], and from device code flow events in
the sign-in logs being tied to the authentication protocol property.[^26] The
redemption is an `Entra AADNonInteractiveUserSignInLogs (Device code
redemption)` row; that placement follows from the non-interactive sign-in
definition and its authorization code example in [Telemetry Surfaces]. Whether
the device code request is recorded is not established, so the request node
carries no label.

#### Detection Data Model

![TRR0000.AZR.A DDM](ddms/trr0000_azr_a.png)

### Procedure B: Multi-Tenant Illicit Consent Grant (TRR0000.AZR.B)

This procedure covers consent in the victim tenant to an application the
adversary registered elsewhere. Its two branches end in different token
issuances: a delegated branch that redeems an authorization code, and an
application branch that issues a client-credentials token to the consented
application's service principal. The consent settings, roles, and endpoint are
stated in [OAuth Consent Framework], and the request shapes in [Authorization
Code Flow Internals] and [Client Credentials and Federated Credential Exchange].

The prerequisite is an application registered with the sign-in audience
`AzureADMultipleOrgs` or `AzureADandPersonalMicrosoftAccount`, each of which
admits work or school accounts from any organization's tenant.[^66] An
application object is the global representation for use across all tenants and
its service principal is the local representation in a specific tenant.[^67] The
registration is drawn gray because it happens outside the victim tenant, in the
application's home tenant.

On the delegated branch the victim authenticates at `/oauth2/v2.0/authorize`.
When a user from a different tenant signs in to the application for the first
time, Entra ID asks the user to consent to the requested permissions.[^31] If
the user consents, a service principal for the application is created in the
user's tenant and a delegation recording the consent is created in the
directory.[^31] The platform then returns the authorization code to the
registered `redirect_uri`, and the adversary redeems it at `/oauth2/v2.0/token`.
Whether the victim may consent at all depends on the tenant settings stated in
[OAuth Consent Framework]. The consent prompt appears when no previous record of
user or admin consent for the required permissions exists.[^34] It follows that
where a grant created earlier exists, the delegated branch can pass through the
sign-in and the code redemption with that earlier consent as its prerequisite.
Whether the consent audit rows are written again in that case is not documented.

On the application branch a tenant administrator signs in at the admin consent
endpoint. The documented success redirect in [OAuth Consent Framework] lists no
`code` parameter, and the application proceeds directly to a `/token` request
with the client-credentials grant and its own credential.[^3]

The victim's interactive sign-in is an `Entra SigninLogs (Interactive sign-in)`
row whose `AppId` column identifies the application.[^46] On either branch, the
first consent to the application in the tenant produces an `Entra AuditLogs (Add
service principal)` row; that follows from user consent and admin consent each
creating the service principal in the victim tenant.[^31][^67] On the delegated
branch the consent also produces `Entra AuditLogs (Consent to application)` and
`Entra AuditLogs (Add delegated permission grant)` rows, the user-consent and
delegated-access activities in [Telemetry Surfaces]. On the application branch
the admin consent carries the label `Entra AuditLogs (Add app role assignment to
service principal)`, the app-only access activity in [Telemetry Surfaces]. That
placement follows from application permissions being grantable through a consent
experience, as stated in [OAuth Consent Framework]. The code redemption is an
`Entra AADNonInteractiveUserSignInLogs (Authorization code redemption)` row, the
non-interactive sign-in example in [Telemetry Surfaces]. The client-credentials
issuance is an `Entra AADServicePrincipalSignInLogs (Client credentials flow
sign-in)` row carrying `ClientCredentialType`, `ServicePrincipalId`, and
`AppId`.[^49] That the row lands in the victim tenant's log follows from consent
creating the service principal there and the token request naming that tenant in
its path.

#### Detection Data Model

![TRR0000.AZR.B DDM](ddms/trr0000_azr_b.png)

### Procedure C: Managed Identity Token Retrieval (TRR0000.AZR.C)

This procedure covers a token request from code the adversary runs on an Azure
compute resource with an attached managed identity, against the managed identity
token endpoint; the endpoint, header, and caching facts are stated in [The
Instance Metadata Service].

The prerequisite, drawn gray, is code execution on the resource with a
system-assigned or user-assigned identity: an Azure VM, App Service, Function
App, Container Instance, AKS node, Container App, Service Fabric application, or
Automation Account. Code execution on the resource is the access vector, outside
the technique's observable boundary, and any record the vector produces belongs
to the vector's own technique. From the resource the adversary issues the token
request to the managed identity token endpoint, using the endpoint and header of
that host, and receives a bearer access token. On AKS, it follows from the IMDS
default in [The Instance Metadata Service] that code in a pod can request a
token for an identity attached to the node, and that request is an instance of
this procedure. The kubelet managed identity is assigned to AKS nodes[^68] and
has no default permissions.[^69]

On an Azure VM or an AKS node, the request is observable as `Linux auditd
(connect syscall)` and `Sysmon 3 (NetworkConnect)` records for the connection to
the token endpoint address. Whether the request produces a host record on the
other resource types is not established. The issuance is an `Entra
AADManagedIdentitySignInLogs (Token issuance)` row carrying
`ServicePrincipalId`, `ResourceIdentity`, `ResourceDisplayName`, and
`ManagedServiceIdentity`.[^50] That on an Azure VM a request served from the
subsystem cache writes no row follows from the cache behavior in [The Instance
Metadata Service] and the sign-in table in [Telemetry Surfaces]. The adversary's
request to the IMDS endpoint itself has no documented Entra record.

#### Detection Data Model

![TRR0000.AZR.C DDM](ddms/trr0000_azr_c.png)

### Procedure D: AKS Workload Identity Token Theft (TRR0000.AZR.D)

This procedure covers acquisition of a Kubernetes service account JWT that a
federated identity credential trusts, followed by its exchange at the Entra
token endpoint for an access token issued to the federated application. The
exchange request and the credential matching rules are stated in [Client
Credentials and Federated Credential Exchange], and the two branches differ in
how the assertion is obtained.

On the projected-token branch the prerequisite, drawn gray for the reason given
in Procedure C, is code execution in a pod of an AKS cluster configured for
Microsoft Entra Workload ID. Only pods carrying the label
`azure.workload.identity/use: "true"` are mutated by the admission webhook to
inject the Azure environment variables and the projected service account token
volume, and the service account can carry the
`azure.workload.identity/client-id` annotation naming the Entra application.[^4]
The adversary reads the projected token from the file named by
`AZURE_FEDERATED_TOKEN_FILE`,
`/var/run/secrets/azure/tokens/azure-identity-token` in the documented example,
a mount path that is an implementation detail of the webhook and can change.[^4]
The token is a signed JWT[^70] that Kubernetes refreshes in place before it
expires.[^4] The read is observable as `Linux auditd (open/openat syscall)`
under a rule keyed on that file. `/proc/<pid>/environ` holds the initial
environment set at `execve`.[^71] That a read of it yields the token file path
and not the token follows from that content and from
`AZURE_FEDERATED_TOKEN_FILE` holding a path. `/proc/<pid>/mem` gives access to a
process's memory pages under a ptrace access-mode check.[^72] The `environ` and
`mem` reads open a procfs path rather than the token path; it follows that an
audit rule keyed on the token file covers the token-file read and neither procfs
read.

On the TokenRequest branch the adversary mints the assertion. The operation
requires `create` on `serviceaccounts/token`, the right that lets users create
TokenRequests to issue tokens for existing service accounts,[^73] carried as the
operation's `Permission`. The TokenRequest subresource of a ServiceAccount, a
`POST` to `/api/v1/namespaces/{namespace}/serviceaccounts/{name}/token`, issues
a time-bound token for that service account with the audiences the caller
requests.[^74][^75] The federated identity credential for a service account
names the subject `system:serviceaccount:<namespace>:<name>` and lists the
audiences that may appear in the token, with `api://AzureADTokenExchange` as the
recommended value.[^76] Direct workload identity federation on AKS takes a token
with that audience; when identity bindings are enabled, the default projected
token carries `api://AKSIdentityBinding` instead.[^4] A token issued through a
TokenRequest for the same service account carries that subject and the requested
audience.[^75][^76] The service account token issuer asserts its configured
identifier in the `iss` claim of the tokens it issues,[^77] and the documented
AKS setup creates the federated identity credential with the service account
issuer and subject.[^78] That Entra ID accepts a minted token follows from the
credential's match on issuer, subject, and audience, stated in [Client
Credentials and Federated Credential Exchange]; the exchange is documented only
for the projected token. The request is observable as an `AKSAudit (Kubernetes
API server audit)` row. That the row carries `Verb` `create` and `ObjectRef`
resource `serviceaccounts`, subresource `token` follows from the POST-to-create
mapping and the audit event fields in [Telemetry Surfaces]. The kubelet obtains
projected service account tokens through the TokenRequest API,[^74] so its own
requests would carry the same verb and object reference.

Either assertion is presented at `/oauth2/v2.0/token` for the federated
application. An exchange whose federated identity credential is on an
application registration is an `Entra AADServicePrincipalSignInLogs (Federated
credential exchange)` row identified by `ClientCredentialType` and
`FederatedCredentialId`.[^49] The documented AKS setup federates a user-assigned
managed identity,[^78] and `AADManagedIdentitySignInLogs` also carries
`FederatedCredentialId`.[^50] Which table records an exchange whose credential
is on a user-assigned managed identity is not documented. The
`AADServicePrincipalSignInLogs` `IPAddress` column is the address of the client
used to sign in.[^49] By default AKS egresses through an AKS-assigned Standard
Load Balancer public IP, and the NAT gateway outbound types egress through Azure
NAT Gateway.[^79] That the row for an exchange sent from a pod records the
cluster's egress address rather than the pod's follows from the column
definition and the egress configuration.

#### Detection Data Model

![TRR0000.AZR.D DDM](ddms/trr0000_azr_d.png)

## Available Emulation Tests

| ID      | Link                                                        |
|---------|-------------------------------------------------------------|
| T1528-1 | [Atomic Test 1 - Functions Code Injection via Blob Upload]  |
| T1528-2 | [Atomic Test 2 - Functions Code Injection via File Share]   |

## References

- [MITRE ATT&CK T1528]
- [Azure Threat Research Matrix AZT203]
- [Azure Threat Research Matrix AZT601]
- [RFC 6750 OAuth 2.0 Bearer Token Usage]
- [Microsoft Token Theft Playbook]
- [RFC 8628 OAuth 2.0 Device Authorization Grant]
- [Microsoft Identity Platform OAuth 2.0 Device Authorization Grant]
- [Microsoft Identity Platform OAuth 2.0 Authorization Code Flow]
- [Microsoft Identity Platform Client Credentials Flow]
- [Microsoft Identity Platform Admin Consent Endpoint]
- [Azure Instance Metadata Service]
- [Use Managed Identities on an Azure VM to Acquire Access Tokens]
- [Use Microsoft Entra Workload ID on AKS]
- [Microsoft Identity Platform Workload Identity Federation]
- [Kubernetes TokenRequest API Reference]
- [Azure Monitor SigninLogs Table]
- [Azure Monitor AADNonInteractiveUserSignInLogs Table]
- [Azure Monitor AADServicePrincipalSignInLogs Table]
- [Azure Monitor AADManagedIdentitySignInLogs Table]
- [Azure Monitor AuditLogs Table]
- [Azure Monitor AKSAudit Table]
- [Microsoft Entra Audit Activity Reference]
- [Sysmon]
- [Linux auditctl Manual Page]
- [Microsoft Security Blog - Storm-2372 Device Code Phishing]
- [Microsoft Security Blog - AI-Enabled Device Code Phishing 2026]
- [Microsoft Security Blog - CaptiveCrunch]
- [Huntress - Railway PaaS M365 Token Replay Campaign]
- [Sekoia - EvilTokens Device Code Phishing Part 1]
- [Proofpoint - Phishing for Device Code Authorization Account Takeover]
- [Atomic Red Team T1528]

[T1078.004]: https://attack.mitre.org/techniques/T1078/004/
[T1528]: https://attack.mitre.org/techniques/T1528/
[T1550.001]: https://attack.mitre.org/techniques/T1550/001/
[T1552]: https://attack.mitre.org/techniques/T1552/
[T1552.001]: https://attack.mitre.org/techniques/T1552/001/
[AZT203]: https://microsoft.github.io/Azure-Threat-Research-Matrix/InitialAccess/AZT203/AZT203/
[AZT601]: https://microsoft.github.io/Azure-Threat-Research-Matrix/CredentialAccess/AZT601/AZT601/
[TRR0034]: https://github.com/tired-labs/techniques/blob/main/reports/trr0034/azr/README.md

[Device Authorization Grant Internals]: #device-authorization-grant-internals
[Authorization Code Flow Internals]: #authorization-code-flow-internals
[Client Credentials and Federated Credential Exchange]: #client-credentials-and-federated-credential-exchange
[The Instance Metadata Service]: #the-instance-metadata-service
[OAuth Consent Framework]: #oauth-consent-framework
[Telemetry Surfaces]: #telemetry-surfaces

[MITRE ATT&CK T1528]: https://attack.mitre.org/techniques/T1528/
[Azure Threat Research Matrix AZT203]: https://microsoft.github.io/Azure-Threat-Research-Matrix/InitialAccess/AZT203/AZT203/
[Azure Threat Research Matrix AZT601]: https://microsoft.github.io/Azure-Threat-Research-Matrix/CredentialAccess/AZT601/AZT601/
[RFC 6750 OAuth 2.0 Bearer Token Usage]: https://datatracker.ietf.org/doc/html/rfc6750
[Microsoft Token Theft Playbook]: https://learn.microsoft.com/en-us/security/operations/token-theft-playbook
[RFC 8628 OAuth 2.0 Device Authorization Grant]: https://datatracker.ietf.org/doc/html/rfc8628
[Microsoft Identity Platform OAuth 2.0 Device Authorization Grant]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
[Microsoft Identity Platform OAuth 2.0 Authorization Code Flow]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
[Microsoft Identity Platform Client Credentials Flow]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
[Microsoft Identity Platform Admin Consent Endpoint]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent
[Azure Instance Metadata Service]: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
[Use Managed Identities on an Azure VM to Acquire Access Tokens]: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token
[Use Microsoft Entra Workload ID on AKS]: https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
[Microsoft Identity Platform Workload Identity Federation]: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
[Kubernetes TokenRequest API Reference]: https://raw.githubusercontent.com/kubernetes/website/release-1.34/content/en/docs/reference/kubernetes-api/authentication-resources/token-request-v1.md
[Azure Monitor SigninLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
[Azure Monitor AADNonInteractiveUserSignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs
[Azure Monitor AADServicePrincipalSignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs
[Azure Monitor AADManagedIdentitySignInLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs
[Azure Monitor AuditLogs Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
[Azure Monitor AKSAudit Table]: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit
[Microsoft Entra Audit Activity Reference]: https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities
[Sysmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[Linux auditctl Manual Page]: https://man7.org/linux/man-pages/man8/auditctl.8.html
[Microsoft Security Blog - Storm-2372 Device Code Phishing]: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
[Microsoft Security Blog - AI-Enabled Device Code Phishing 2026]: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
[Microsoft Security Blog - CaptiveCrunch]: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
[Huntress - Railway PaaS M365 Token Replay Campaign]: https://www.huntress.com/blog/railway-paas-m365-token-replay-campaign
[Sekoia - EvilTokens Device Code Phishing Part 1]: https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1
[Proofpoint - Phishing for Device Code Authorization Account Takeover]: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover
[Atomic Red Team T1528]: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1528
[Atomic Test 1 - Functions Code Injection via Blob Upload]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md#atomic-test-1-azure---functions-code-upload---functions-code-injection-via-blob-upload
[Atomic Test 2 - Functions Code Injection via File Share]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md#atomic-test-2-azure---functions-code-upload---functions-code-injection-via-file-share-modification-to-retrieve-the-functions-identity-access-token

[^1]: [Microsoft Identity Platform OAuth 2.0 and OpenID Connect Protocols](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols)
[^2]: [Microsoft Identity Platform OAuth 2.0 Device Authorization Grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
[^3]: [Microsoft Identity Platform Client Credentials Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
[^4]: [Use Microsoft Entra Workload ID on AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
[^5]: [RFC 8628 OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
[^6]: [Dynamics 365 Warehouse Management App User-Based Authentication](https://learn.microsoft.com/dynamics365/supply-chain/warehousing/warehouse-app-authenticate-user-based)
[^7]: [MSAL Authentication Flows](https://learn.microsoft.com/entra/identity-platform/msal-authentication-flows)
[^8]: [Microsoft Identity Platform Breaking Changes Reference](https://learn.microsoft.com/entra/identity-platform/reference-breaking-changes)
[^9]: [Microsoft Identity Platform OAuth 2.0 Authorization Code Flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
[^10]: [Microsoft Identity Platform Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
[^11]: [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
[^12]: [Use Managed Identities on an Azure VM to Acquire Access Tokens](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
[^13]: [App Service Managed Identity Overview](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)
[^14]: [App Service Environment Variables and App Settings Reference](https://learn.microsoft.com/en-us/azure/app-service/reference-app-settings)
[^15]: [Azure Container Apps Managed Identities](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity)
[^16]: [Enable Managed Identity for Azure Automation](https://learn.microsoft.com/en-us/azure/automation/enable-managed-identity-for-automation)
[^17]: [Service Fabric Managed Identity in Application Code](https://learn.microsoft.com/en-us/azure/service-fabric/how-to-managed-identity-service-fabric-app-code)
[^18]: [Azure Container Instances Managed Identity](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity)
[^19]: [AKS IMDS Restriction](https://learn.microsoft.com/en-us/azure/aks/imds-restriction)
[^20]: [Microsoft Identity Platform Access Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
[^21]: [Microsoft Identity Platform Access Token Claims Reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
[^22]: [Microsoft Identity Web Token Binding](https://learn.microsoft.com/entra/msidweb/call-downstream-apis/token-binding)
[^23]: [Microsoft Identity Platform Configurable Token Lifetimes](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes)
[^24]: [Microsoft Entra Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
[^25]: [Managed Identities for Azure Resources Developer Guidelines](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview-for-developers)
[^26]: [Microsoft Entra Conditional Access Authentication Flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
[^27]: [Microsoft Entra Security Defaults](https://learn.microsoft.com/entra/fundamentals/security-defaults)
[^28]: [Microsoft Entra Conditional Access Grant Controls](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-grant)
[^29]: [Microsoft Identity Platform Permissions and Consent Overview](https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview)
[^30]: [Microsoft Entra Application and Delegated Permission Access Tokens](https://learn.microsoft.com/troubleshoot/entra/entra-id/app-integration/application-delegated-permission-access-tokens-identity-platform)
[^31]: [Microsoft Identity Platform Convert App to Multitenant](https://learn.microsoft.com/entra/identity-platform/howto-convert-app-to-be-multi-tenant)
[^32]: [Microsoft Graph oAuth2PermissionGrant Resource](https://learn.microsoft.com/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0)
[^33]: [Microsoft Graph Service Principal App Role Assignment](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-approleassignedto?view=graph-rest-1.0)
[^34]: [Microsoft Entra User and Admin Consent Overview](https://learn.microsoft.com/entra/identity/enterprise-apps/user-admin-consent-overview)
[^35]: [Microsoft Identity Platform Publisher Verification Overview](https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview)
[^36]: [Microsoft Entra Risk-Based Step-Up Consent](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-risk-based-step-up-consent)
[^37]: [Microsoft Entra Manage App Consent Policies](https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies)
[^38]: [Microsoft Entra Grant Tenant-Wide Admin Consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
[^39]: [Microsoft Entra Built-In Roles Reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
[^40]: [Microsoft Identity Platform Admin Consent Endpoint](https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent)
[^41]: [Microsoft Entra Sign-In Logs Overview](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
[^42]: [Microsoft Entra Interactive User Sign-Ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-interactive-sign-ins)
[^43]: [Microsoft Entra Non-Interactive User Sign-Ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins)
[^44]: [Microsoft Entra Service Principal Sign-Ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins)
[^45]: [Microsoft Entra Managed Identity Sign-Ins](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-managed-identity-sign-ins)
[^46]: [Azure Monitor SigninLogs Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
[^47]: [Microsoft Entra Diagnostic Settings Log Options](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options)
[^48]: [Azure Monitor AADNonInteractiveUserSignInLogs Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
[^49]: [Azure Monitor AADServicePrincipalSignInLogs Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)
[^50]: [Azure Monitor AADManagedIdentitySignInLogs Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)
[^51]: [Microsoft Graph signIn Resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta)
[^52]: [Azure Monitor AuditLogs Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
[^53]: [Microsoft Entra Audit Activity Reference](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities)
[^54]: [Microsoft Entra Audit Logs for App Permissions](https://learn.microsoft.com/entra/identity/enterprise-apps/app-perms-audit-logs)
[^55]: [Linux auditctl Manual Page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
[^56]: [Red Hat Auditing the System](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
[^57]: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[^58]: [Sysmon Common Event Manifest](https://raw.githubusercontent.com/microsoft/SysmonCommon/main/manifest.xml)
[^59]: [Linux open Manual Page](https://man7.org/linux/man-pages/man2/open.2.html)
[^60]: [Azure Monitor AKSAudit Table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit)
[^61]: [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
[^62]: [Kubernetes Audit API Reference](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
[^63]: [Kubernetes Authorization Overview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
[^64]: [Microsoft Security Blog - Storm-2372 Device Code Phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
[^65]: [Microsoft Security Blog - CaptiveCrunch](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
[^66]: [Microsoft Identity Platform App Manifest Reference](https://learn.microsoft.com/entra/identity-platform/reference-microsoft-graph-app-manifest)
[^67]: [Microsoft Identity Platform Application and Service Principal Objects](https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals)
[^68]: [AKS Service Permissions Reference](https://learn.microsoft.com/en-us/azure/aks/aks-service-permissions)
[^69]: [AKS Managed Identity Overview](https://learn.microsoft.com/en-us/azure/aks/managed-identity-overview)
[^70]: [Kubernetes Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
[^71]: [Linux proc_pid_environ Manual Page](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html)
[^72]: [Linux proc_pid_mem Manual Page](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
[^73]: [Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
[^74]: [Kubernetes Service Account Administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
[^75]: [Kubernetes TokenRequest API Reference](https://raw.githubusercontent.com/kubernetes/website/release-1.34/content/en/docs/reference/kubernetes-api/authentication-resources/token-request-v1.md)
[^76]: [Microsoft Entra Workload Identity Federation Create Trust](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust)
[^77]: [Kubernetes kube-apiserver Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
[^78]: [Deploy Microsoft Entra Workload ID on AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster)
[^79]: [Customize Cluster Egress with Outbound Types in AKS](https://learn.microsoft.com/en-us/azure/aks/egress-outboundtype)

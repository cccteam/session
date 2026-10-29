# Changelog

## [0.13.18](https://github.com/cccteam/session/compare/v0.13.17...v0.13.18) (2026-10-29)


### Features

* a directory sign-in accepts an invitation only as the invited address; another address is refused with `invitation_address`, the invitation left standing ([#319](https://github.com/cccteam/session/issues/319)) ([4ee9727](https://github.com/cccteam/session/commit/4ee9727c349afb6fe59fc1d8f52107905a70f00d))
* the invitation's Open answer and the methods answer's standing block carry `accountExists` and `hasPassword`, what account holds the invited address, so the login page can show the ways that accept it ([#319](https://github.com/cccteam/session/issues/319)) ([4ee9727](https://github.com/cccteam/session/commit/4ee9727c349afb6fe59fc1d8f52107905a70f00d))

## [0.13.17](https://github.com/cccteam/session/compare/v0.13.16...v0.13.17) (2026-10-29)


### Bug Fixes

* the trusted device cookie holds one token per user, so two people who share a browser, or one person with two accounts, each stay remembered after the second factor: a sign-in reads the signing-in user's token alone, a held sign-in drops that user's entry alone, ForgetTrustedDevice forgets the session user's device and no other, at most five people per browser, and the one-token cookie of earlier releases is still read ([#317](https://github.com/cccteam/session/issues/317)) ([1e253a1](https://github.com/cccteam/session/commit/1e253a1920eadba0264d38f6219c7dea08c27c55))

## [0.13.16](https://github.com/cccteam/session/compare/v0.13.15...v0.13.16) (2026-10-29)


### Bug Fixes

* a front-channel logout naming no issuer on a Microsoft registration serving several tenants ends the sessions recorded under the registration's declared issuers, as Entra sends the session id alone, instead of answering 400 and leaving them open ([#315](https://github.com/cccteam/session/issues/315)) ([1788bfd](https://github.com/cccteam/session/commit/1788bfd8b38bbb2555e338f210f2c7fa6d445b88))

## [0.13.15](https://github.com/cccteam/session/compare/v0.13.14...v0.13.15) (2026-10-29)


### Features

* the Google and Entra login routes accept ?prompt=select_account and pass it to the provider as its prompt, so a login page can ask for the account chooser after a refusal or under "Use a different account" instead of sending a person round the same refusal; any other prompt value is refused with 400; both Authenticator interfaces take the hints as signin.LoginOptions ([#313](https://github.com/cccteam/session/issues/313)) ([d6cfe71](https://github.com/cccteam/session/commit/d6cfe7129678d56270a6a2349c2c443b40882586))


### Bug Fixes

* the OIDC callback refuses a provider's error answer (error=access_denied when the person cancelled at its chooser) before any token exchange, so the login page is always reached with a code ([#313](https://github.com/cccteam/session/issues/313)) ([d6cfe71](https://github.com/cccteam/session/commit/d6cfe7129678d56270a6a2349c2c443b40882586))


### Code Upgrade

* **deps:** bump the go-dependencies group with 5 updates ([#312](https://github.com/cccteam/session/issues/312)) ([99d25bd](https://github.com/cccteam/session/commit/99d25bd80e42e99905cde4ba0a6fb5356a6f06e8))

## [0.13.14](https://github.com/cccteam/session/compare/v0.13.13...v0.13.14) (2026-10-28)


### Features

* every session carries a second factor when the policy asks: a sign-in's attestation by evidence (an amr naming mfa) or by declaration (a Workspace or tenant declared Attesting()), a trusted device the person asked to be remembered, or the email code the library mails and verifies, with an administrator's reset ([d83a272](https://github.com/cccteam/session/commit/d83a272e64090351a6fedbfe162dc194b6de0af0))
* the pending status reports the email code's state, the methods list names the code routes, and the session's auth events record the attestation (attested-by-evidence, attested-by-declaration), the trusted device and the code (email-code) ([d83a272](https://github.com/cccteam/session/commit/d83a272e64090351a6fedbfe162dc194b6de0af0))

## [0.13.13](https://github.com/cccteam/session/compare/v0.13.12...v0.13.13) (2026-10-27)


### Features

* a tenant's declaration of a directory decides a stranger's first sign-in: a default seat admits and seats them, no seat refuses them by invitation only (invitation_only), and a person the tenant already seated is admitted ([#308](https://github.com/cccteam/session/issues/308)) ([d766792](https://github.com/cccteam/session/commit/d766792216ebdaeefceaabd7177c6f06fe59a62b))

## [0.13.12](https://github.com/cccteam/session/compare/v0.13.11...v0.13.12) (2026-10-26)


### Features

* a registration that synchronizes roles stands alone on its Auth; registering it beside another method, or any method beside it, is refused with the two ways out ([#306](https://github.com/cccteam/session/issues/306)) ([aeb6303](https://github.com/cccteam/session/commit/aeb63030c6b718dd2423ce1d9bc330bd065b731b))

## [0.13.11](https://github.com/cccteam/session/compare/v0.13.10...v0.13.11) (2026-10-26)


### Features

* a command-line program signs in to a machine outlet through the device flow: the deviceflow package runs the flow, keeps the pair in the person's config and refreshes it ([#304](https://github.com/cccteam/session/issues/304)) ([6b0a5a9](https://github.com/cccteam/session/commit/6b0a5a9002d8ee4f3f7935e5956b14ecd717e127))

## [0.13.10](https://github.com/cccteam/session/compare/v0.13.9...v0.13.10) (2026-10-25)


### Features

* machine outlets take bearer tokens the Auth issues: a person's application tokens, and the access and refresh tokens a command-line client obtains through the device flow (RFC 8628) with the person's approval ([#302](https://github.com/cccteam/session/issues/302)) ([669dc31](https://github.com/cccteam/session/commit/669dc31936559f1657106548f337ef31be771769))
* the request's log entry and span name the token that authenticated a machine-outlet request (token.id, token.kind, token.name or token.client), and a refresh rotates the pair while a reuse revokes the family ([#302](https://github.com/cccteam/session/issues/302)) ([669dc31](https://github.com/cccteam/session/commit/669dc31936559f1657106548f337ef31be771769))

## [0.13.9](https://github.com/cccteam/session/compare/v0.13.8...v0.13.9) (2026-10-24)


### Features

* an external sign-in resolves to the user who holds its verified address when no user is under the sign-in name, is held for the password confirmation when that user has one, and is never provisioned as a second user over an address another user holds ([#300](https://github.com/cccteam/session/issues/300)) ([5d577a8](https://github.com/cccteam/session/commit/5d577a84f5a59debbe9f2415308e68fdaffb16d7))

## [0.13.8](https://github.com/cccteam/session/compare/v0.13.7...v0.13.8) (2026-10-24)


### Features

* an invitation is refused when no sign-in method the login page offers could admit the address, so the sender learns it instead of the invitee at the sign-in ([#298](https://github.com/cccteam/session/issues/298)) ([33b95c3](https://github.com/cccteam/session/commit/33b95c332e0a90bbaecb155db7fc863a32f16780))
* both invitation answers name the registrations that could admit the invited address, so the login page offers only the buttons that can admit the invitee ([#298](https://github.com/cccteam/session/issues/298)) ([33b95c3](https://github.com/cccteam/session/commit/33b95c332e0a90bbaecb155db7fc863a32f16780))


### Bug Fixes

* a sign-in that is refused leaves the invitation it carried standing, and an invited sign-in through a linked identity hands the application's grant the user's name ([#298](https://github.com/cccteam/session/issues/298)) ([33b95c3](https://github.com/cccteam/session/commit/33b95c332e0a90bbaecb155db7fc863a32f16780))
* the methods listing reports the invitation the browser carries, so the login page shows it again when a refused directory sign-in sends the browser back without the link's token ([#298](https://github.com/cccteam/session/issues/298)) ([33b95c3](https://github.com/cccteam/session/commit/33b95c332e0a90bbaecb155db7fc863a32f16780))

## [0.13.7](https://github.com/cccteam/session/compare/v0.13.6...v0.13.7) (2026-10-24)


### Bug Fixes

* the mailed messages read as instructions, say how long the link lasts, and end with what to do if it was not you ([#295](https://github.com/cccteam/session/issues/295)) ([c66e96f](https://github.com/cccteam/session/commit/c66e96fd324d86247a85023fca1cc5805c164fb9))
* the session validation test builds each session row inside its subtest ([#296](https://github.com/cccteam/session/issues/296)) ([265e06c](https://github.com/cccteam/session/commit/265e06cca666cd4b8dd50fc4dce8097720bce992))

## [0.13.6](https://github.com/cccteam/session/compare/v0.13.5...v0.13.6) (2026-10-24)


### Bug Fixes

* the Workspace mail driver introduces itself to the relay with the mailbox's domain, which Google's relay requires ([#293](https://github.com/cccteam/session/issues/293)) ([9ac192f](https://github.com/cccteam/session/commit/9ac192fe9a1d92657e55a6f4598f304073ba6820))

## [0.13.5](https://github.com/cccteam/session/compare/v0.13.4...v0.13.5) (2026-10-24)


### Features

* the Workspace mail driver sends from an address separate from the account it logs in with, so a no-reply alias serves as the sender ([#291](https://github.com/cccteam/session/issues/291)) ([76f30f3](https://github.com/cccteam/session/commit/76f30f3f97893cec1d701cb3d7b4ad1f93fe175f))

## [0.13.4](https://github.com/cccteam/session/compare/v0.13.3...v0.13.4) (2026-10-23)


### Features

* invitations, email addresses in two states and open sign-up, each through a mailed link its follower proves ([#290](https://github.com/cccteam/session/issues/290)) ([e30a305](https://github.com/cccteam/session/commit/e30a305ef67c33ec48eff3a0077aecc4a7ca9b67))
* the library sends mail through one interface, with the Google Workspace SMTP relay as the first driver ([#289](https://github.com/cccteam/session/issues/289)) ([ea4350c](https://github.com/cccteam/session/commit/ea4350c762522ca616fc9550df17fe546e24d643))


### Code Upgrade

* **deps:** bump actions/create-github-app-token from 3.2.0 to 3.3.0 in the github-actions group across 1 directory ([#284](https://github.com/cccteam/session/issues/284)) ([afccf4c](https://github.com/cccteam/session/commit/afccf4c7eaeed4ecc0be148f0fc6d1ade29b551c))

## [0.13.3](https://github.com/cccteam/session/compare/v0.13.2...v0.13.3) (2026-10-22)


### Code Upgrade

* **deps:** bump the go-dependencies group with 3 updates ([#285](https://github.com/cccteam/session/issues/285)) ([63979e6](https://github.com/cccteam/session/commit/63979e69f88df1ab135844d069054f8a150cc14c))
* **deps:** Go 1.27.3; crypto/x509 GO-2026-6809 fixed ([#286](https://github.com/cccteam/session/issues/286)) ([45f9d0b](https://github.com/cccteam/session/commit/45f9d0b1a4c69e5d1bb6f773394d0f1f1d7ce28a))

## [0.13.2](https://github.com/cccteam/session/compare/v0.13.1...v0.13.2) (2026-10-21)


### Bug Fixes

* the Spanner driver reads a missing sign-in attempts table as its own error, not as no record on a closed txn ([#282](https://github.com/cccteam/session/issues/282)) ([01b565b](https://github.com/cccteam/session/commit/01b565b531642bd65ef297aaa8fa8a8274b78b06))

## [0.13.1](https://github.com/cccteam/session/compare/v0.13.0...v0.13.1) (2026-10-21)


### Features

* the password method limits failed sign-in attempts per name, with an after-sign-in hook ([#280](https://github.com/cccteam/session/issues/280)) ([ea23748](https://github.com/cccteam/session/commit/ea23748ebe35202fa92f059f13176fc7b6b25202))
* the tenant policy admits a sign-in when one of the person's tenants admits the way they signed in ([#280](https://github.com/cccteam/session/issues/280)) ([ea23748](https://github.com/cccteam/session/commit/ea23748ebe35202fa92f059f13176fc7b6b25202))


### Code Upgrade

* **deps:** Go 1.26.10; crypto/x509 GO-2026-6809 fixed ([#280](https://github.com/cccteam/session/issues/280)) ([ea23748](https://github.com/cccteam/session/commit/ea23748ebe35202fa92f059f13176fc7b6b25202))

## [0.13.0](https://github.com/cccteam/session/compare/v0.12.3...v0.13.0) (2026-10-19)


### ⚠ BREAKING CHANGES

* Auth sessions with several sign-in methods per group: password, Entra ID, Google and WorkOS on one user model ([#265](https://github.com/cccteam/session/issues/265))

### Features

* Auth sessions with several sign-in methods per group: password, Entra ID, Google and WorkOS on one user model ([#265](https://github.com/cccteam/session/issues/265)) ([e2e3c1a](https://github.com/cccteam/session/commit/e2e3c1acadd260fb4a21e91dc14bdbb0556b315a))
* the user API lists and reads users, and a password an operator sets is temporary: the user changes it before anything else is served ([#274](https://github.com/cccteam/session/issues/274)) ([ca39e2d](https://github.com/cccteam/session/commit/ca39e2dd3e3f89a0aae164252d9ad422fd4a8473))


### Documentation

* the Google role sync's naming note says the store resolves a group's lowercase name without regard to case ([#273](https://github.com/cccteam/session/issues/273)) ([f4f9504](https://github.com/cccteam/session/commit/f4f95044090c082ebcbe8e24c10ae012a24625b8))


### Code Upgrade

* **deps:** bump the go-dependencies group across 1 directory with 12 updates ([#276](https://github.com/cccteam/session/issues/276)) ([0157760](https://github.com/cccteam/session/commit/01577605482b0b378ecd0389a21bf48a47bb58f9))

## [0.12.3](https://github.com/cccteam/session/compare/v0.12.2...v0.12.3) (2026-10-11)


### Bug Fixes

* the OIDC sign-in cookie is HttpOnly, dependabot waits a week, and the by-design Semgrep findings are annotated ([#262](https://github.com/cccteam/session/issues/262)) ([15bf6f1](https://github.com/cccteam/session/commit/15bf6f18edb5030f79f248ce0c3815b4539eefec))


### Code Upgrade

* **deps:** bump golang.org/x/sync from 0.23.0 to 0.24.0 in the go-dependencies group ([#264](https://github.com/cccteam/session/issues/264)) ([447e800](https://github.com/cccteam/session/commit/447e800a36cc8ce0a534c272f9d3b4831f90cc15))

## [0.12.2](https://github.com/cccteam/session/compare/v0.12.1...v0.12.2) (2026-10-09)


### Bug Fixes

* request bodies decode with httpio's StructDecoder; the module no longer requires resource ([#260](https://github.com/cccteam/session/issues/260)) ([c6b13bb](https://github.com/cccteam/session/commit/c6b13bb87bd0571ab25f57804b1efe182cd94072))

## [0.12.1](https://github.com/cccteam/session/compare/v0.12.0...v0.12.1) (2026-10-08)


### Code Upgrade

* **deps:** Go 1.26.9 and golang.org/x/net v0.60.0; net/http GO-2026-6612, GO-2026-6613 and GO-2026-6617 fixed ([#257](https://github.com/cccteam/session/issues/257)) ([83b39c9](https://github.com/cccteam/session/commit/83b39c9790a91cc0a6f4c31c4c32174a6e7e1dd9))
* **deps:** the security scan runs golang-security-scan v8.2.1 and names its Grype switch ([#220](https://github.com/cccteam/session/issues/220)) ([a529179](https://github.com/cccteam/session/commit/a5291792947e4f2985d0c42ea82d48cd89ef5729))

## [0.12.0](https://github.com/cccteam/session/compare/v0.11.1...v0.12.0) (2026-10-06)


### ⚠ BREAKING CHANGES

* Replace the OIDC userRoleManager param with a required RoleSync slot ([#241](https://github.com/cccteam/session/issues/241))

### Features

* Add Google Workspace OIDC as a first-class login provider ([#243](https://github.com/cccteam/session/issues/243)) ([294e5b1](https://github.com/cccteam/session/commit/294e5b1cfe522e2bdcad7fc6559aabe207768d2a))
* Impersonated sessions — sessions that operate as a user or a role ([#249](https://github.com/cccteam/session/issues/249)) ([0d5de33](https://github.com/cccteam/session/commit/0d5de3386f092e985223244d0524954a3f18a047))
* Replace the OIDC userRoleManager param with a required RoleSync slot ([#241](https://github.com/cccteam/session/issues/241)) ([941264d](https://github.com/cccteam/session/commit/941264dc4586fc1f5fdd240015e73c0632656eeb))

## [0.11.1](https://github.com/cccteam/session/compare/v0.11.0...v0.11.1) (2026-09-02)


### Bug Fixes

* Delete cookies with the Domain they were written with ([#244](https://github.com/cccteam/session/issues/244)) ([8941fa1](https://github.com/cccteam/session/commit/8941fa1d416afcccdfac63c2feb2b9dc111e1d7a))
* Derive deterministic tid/oid claims for skipAuth logins ([#248](https://github.com/cccteam/session/issues/248)) ([e310105](https://github.com/cccteam/session/commit/e310105e753c307f9acd28d0cf5f8e51e6be6034))

## [0.11.0](https://github.com/cccteam/session/compare/v0.10.1...v0.11.0) (2026-08-25)


### ⚠ BREAKING CHANGES

* Add custom user data and a library-managed OIDC user anchor ([#240](https://github.com/cccteam/session/issues/240))

### Features

* Add custom user data and a library-managed OIDC user anchor ([#240](https://github.com/cccteam/session/issues/240)) ([8276209](https://github.com/cccteam/session/commit/827620969356a9548fc46f822c02a7a7acc699ec))

## [0.10.1](https://github.com/cccteam/session/compare/v0.10.0...v0.10.1) (2026-08-22)


### Bug Fixes

* Move session context checks for DeactivateUser & DeleteUser to handlers ([#232](https://github.com/cccteam/session/issues/232)) ([7b4cd27](https://github.com/cccteam/session/commit/7b4cd279f2c4efa411c3bbe318e1c83a90c2ed93))

## [0.10.0](https://github.com/cccteam/session/compare/v0.9.1...v0.10.0) (2026-08-19)


### ⚠ BREAKING CHANGES

* Add support for custom session data ([#231](https://github.com/cccteam/session/issues/231))
* Regenerate the session on password change ([#225](https://github.com/cccteam/session/issues/225))

### Features

* Add support for custom session data ([#231](https://github.com/cccteam/session/issues/231)) ([6cbf375](https://github.com/cccteam/session/commit/6cbf375d5eb9c8e7bdc5c8cd656c55d6c9adec7c))
* Regenerate the session on password change ([#225](https://github.com/cccteam/session/issues/225)) ([aa976b8](https://github.com/cccteam/session/commit/aa976b805da1d4a2c93eb6c87affab5a9416cb13))


### Bug Fixes

* Bump grpc to v1.82.1 to patch GO-2026-6061 ([#226](https://github.com/cccteam/session/issues/226)) ([c2f1283](https://github.com/cccteam/session/commit/c2f1283813459c7c5361d08d2f0869f688ae70e9))


### Documentation

* Provide detailed documentation for OIDCAzure and how it manages roles ([#229](https://github.com/cccteam/session/issues/229)) ([67228f9](https://github.com/cccteam/session/commit/67228f9eff862a70931b63c09e28b79b56a41782))

## [0.9.1](https://github.com/cccteam/session/compare/v0.9.0...v0.9.1) (2026-07-24)


### Bug Fixes

* bump Go toolchain to 1.26.5 to patch GO-2026-5856 (crypto/tls ECH privacy leak) ([#221](https://github.com/cccteam/session/issues/221)) ([a4f9f1f](https://github.com/cccteam/session/commit/a4f9f1fd3107ac4c4777c35f24eb2dc4713c4dd8))

## [0.9.0](https://github.com/cccteam/session/compare/v0.8.2...v0.9.0) (2026-07-06)


### ⚠ BREAKING CHANGES

* Revert breaking change to `PasswordAuthAPI.ChangeSessionUserUsername()` introduced in v0.8.0 ([#204](https://github.com/cccteam/session/issues/204))

### Features

* Expose DestroyAllUserSessions via the API ([#209](https://github.com/cccteam/session/issues/209)) ([afebbfd](https://github.com/cccteam/session/commit/afebbfddece9e7be46caf0f9b20e0790396c05f7))
* validate credentials PasswordAuth API ([#207](https://github.com/cccteam/session/issues/207)) ([26d9fee](https://github.com/cccteam/session/commit/26d9feec728f29a08050c4cc78c406e05c24f280))


### Bug Fixes

* Revert breaking change to `PasswordAuthAPI.ChangeSessionUserUsername()` introduced in v0.8.0 ([#204](https://github.com/cccteam/session/issues/204)) ([e4ed38c](https://github.com/cccteam/session/commit/e4ed38c13332597c831f637ddc98fb2725f76a4a))
* Update active sessions in place when changing a username ([#204](https://github.com/cccteam/session/issues/204)) ([e4ed38c](https://github.com/cccteam/session/commit/e4ed38c13332597c831f637ddc98fb2725f76a4a))
* Upgrade Go Version for Vuln Fix ([#212](https://github.com/cccteam/session/issues/212)) ([b4f2d41](https://github.com/cccteam/session/commit/b4f2d416639546d3beb6a007f40c42b7f88224a8))


### Code Upgrade

* Bump the github-actions group across 1 directory with 4 updates ([#202](https://github.com/cccteam/session/issues/202)) ([7764aba](https://github.com/cccteam/session/commit/7764abaa1922ced1c8e9dd2a8cf0f1b023c865a1))
* Bump the github-actions group with 3 updates ([#215](https://github.com/cccteam/session/issues/215)) ([aa4f569](https://github.com/cccteam/session/commit/aa4f569349afb8fa30b5cfe508948a1a9d023f54))

## [0.8.2](https://github.com/cccteam/session/compare/v0.8.1...v0.8.2) (2026-05-26)


### Bug Fixes

* Remove hard coded internal server error ([#203](https://github.com/cccteam/session/issues/203)) ([d507fd1](https://github.com/cccteam/session/commit/d507fd1ef9804aa444f2ba8036ccca2c69927bd7))

## [0.8.1](https://github.com/cccteam/session/compare/v0.8.0...v0.8.1) (2026-05-07)


### Bug Fixes

* address Trivy active incident ([#189](https://github.com/cccteam/session/issues/189)) ([96d498e](https://github.com/cccteam/session/commit/96d498e25c8df4c48273c577995708d39fa0160c))
* grant required permissions and add manual trigger to security-scan workflow ([#200](https://github.com/cccteam/session/issues/200)) ([577b843](https://github.com/cccteam/session/commit/577b843d96b3237b02bb78cad194385d9eec6b92))


### Code Upgrade

* Bump the github-actions group with 3 updates ([#183](https://github.com/cccteam/session/issues/183)) ([863a903](https://github.com/cccteam/session/commit/863a903d79ad56197b0810e0f47570644a4bccd0))
* Bump the github-actions group with 3 updates ([#185](https://github.com/cccteam/session/issues/185)) ([d7ad018](https://github.com/cccteam/session/commit/d7ad01824c125ccc53ef780fb68158fc509890cd))
* Upgrade Go toolchain, vulnerable deps, and pinned workflows ([#197](https://github.com/cccteam/session/issues/197)) ([229ffe4](https://github.com/cccteam/session/commit/229ffe400b84c8f41af35f80a52b40e48dad194b))

## [0.8.0](https://github.com/cccteam/session/compare/v0.7.4...v0.8.0) (2026-02-21)


### ⚠ BREAKING CHANGES

* Update the user's session as part of changing their username ([#181](https://github.com/cccteam/session/issues/181))

### Bug Fixes

* Update the user's session as part of changing their username ([#181](https://github.com/cccteam/session/issues/181)) ([f661bea](https://github.com/cccteam/session/commit/f661beaacb9a0d0f7cd9b050ddb294cb6917ba7c))

## [0.7.4](https://github.com/cccteam/session/compare/v0.7.3...v0.7.4) (2026-02-09)


### Features

* Add handler for changing username ([#176](https://github.com/cccteam/session/issues/176)) ([2d11cd0](https://github.com/cccteam/session/commit/2d11cd05403784894a14228b3162494ad00fd603))
* Adds functionality to the API to change a username ([#176](https://github.com/cccteam/session/issues/176)) ([2d11cd0](https://github.com/cccteam/session/commit/2d11cd05403784894a14228b3162494ad00fd603))


### Bug Fixes

* Fix go vulnerability GO-2026-4337 ([#177](https://github.com/cccteam/session/issues/177)) ([75dfaa7](https://github.com/cccteam/session/commit/75dfaa785b1a2dcfed5c139ee8893bd88cebf9ba))


### Code Upgrade

* Bump Go and go-dependencies ([#177](https://github.com/cccteam/session/issues/177)) ([75dfaa7](https://github.com/cccteam/session/commit/75dfaa785b1a2dcfed5c139ee8893bd88cebf9ba))

## [0.7.3](https://github.com/cccteam/session/compare/v0.7.2...v0.7.3) (2026-01-28)


### Features

* allow login with username case mismatch ([#172](https://github.com/cccteam/session/issues/172)) ([e70830d](https://github.com/cccteam/session/commit/e70830db5acb6a179e881e960e90477c43ab13f7))


### Bug Fixes

* Add missing Username and SessionID log attributes for Preauth Login ([#174](https://github.com/cccteam/session/issues/174)) ([b676d33](https://github.com/cccteam/session/commit/b676d33af2165cb4f0e540b2580903949bfe9065))


### Code Upgrade

* Bump github.com/cccteam/ccc/resource from 0.9.4 to 0.9.5 in the go-dependencies group ([#171](https://github.com/cccteam/session/issues/171)) ([3baf017](https://github.com/cccteam/session/commit/3baf01794c59ad873e97dd6f2653f7ed0868eedb))
* Bump the github-actions group with 3 updates ([#170](https://github.com/cccteam/session/issues/170)) ([432927f](https://github.com/cccteam/session/commit/432927fdf0551fa64c0b0f181be5af6b7c77e251))

## [0.7.2](https://github.com/cccteam/session/compare/v0.7.1...v0.7.2) (2026-01-22)


### Features

* Enhance the cookie.Values API to handle storing anything that can be json encoded ([#168](https://github.com/cccteam/session/issues/168)) ([8e3dd03](https://github.com/cccteam/session/commit/8e3dd03a79e8fe38bebf064a9d1e9ac36c0f6c6f))

## [0.7.1](https://github.com/cccteam/session/compare/v0.7.0...v0.7.1) (2026-01-20)


### Features

* Add ValdateSession to the OIDC API ([#166](https://github.com/cccteam/session/issues/166)) ([c43e2bb](https://github.com/cccteam/session/commit/c43e2bb6434416a4d455d867fc490ce7bb84b468))


### Bug Fixes

* Fix AzureOIDC Login handler to redirect back into the app if an error occures ([#166](https://github.com/cccteam/session/issues/166)) ([c43e2bb](https://github.com/cccteam/session/commit/c43e2bb6434416a4d455d867fc490ce7bb84b468))


### Code Upgrade

* Bump the github-actions group with 3 updates ([#151](https://github.com/cccteam/session/issues/151)) ([a884c2c](https://github.com/cccteam/session/commit/a884c2cbf63e4888aebd80c4ad546db61591e19f))

## [0.7.0](https://github.com/cccteam/session/compare/v0.6.2...v0.7.0) (2026-01-18)


### ⚠ BREAKING CHANGES

* Change package interface to take in cookieKey instead of securecookie.SecureCookie ([#159](https://github.com/cccteam/session/issues/159))

### Features

* Add API to PasswordAuth to provide access to handler internals ([#157](https://github.com/cccteam/session/issues/157)) ([060bbca](https://github.com/cccteam/session/commit/060bbca24f1098358de014bb855f7785b806f9cb))
* Add API to Preauth to provide access to handler internals ([#157](https://github.com/cccteam/session/issues/157)) ([060bbca](https://github.com/cccteam/session/commit/060bbca24f1098358de014bb855f7785b806f9cb))
* Add cookie options for XSRF token ([#155](https://github.com/cccteam/session/issues/155)) ([167a9fc](https://github.com/cccteam/session/commit/167a9fc4b6fe631bd3ff6f3f2d540fa65717bfd9))
* Replace securecookie with paseto for fast modern encryption ([#160](https://github.com/cccteam/session/issues/160)) ([f3e6d4f](https://github.com/cccteam/session/commit/f3e6d4f704051603735343636741c2d2dd77dfa3))


### Bug Fixes

* Fix cookie upgrade bug where SameSite mode was not being recorded in cookie ([#165](https://github.com/cccteam/session/issues/165)) ([901c6e7](https://github.com/cccteam/session/commit/901c6e7952226ddd78b2bfdde88c22afe87e43d7))
* Fix long standing issue with expiring XSRF Token issue on Login forms ([#160](https://github.com/cccteam/session/issues/160)) ([f3e6d4f](https://github.com/cccteam/session/commit/f3e6d4f704051603735343636741c2d2dd77dfa3))
* Initial value for PasswordAuth SameSiteStrictMode should be strict ([#158](https://github.com/cccteam/session/issues/158)) ([c3b533b](https://github.com/cccteam/session/commit/c3b533babc637b5f41be7a4bdd6e2f3526b889cc))


### Code Refactoring

* Change package interface to take in cookieKey instead of securecookie.SecureCookie ([#159](https://github.com/cccteam/session/issues/159)) ([c21f645](https://github.com/cccteam/session/commit/c21f64517bd6168f10c51493071e1d7b7be43aa8))
* Expose cookie management via API ([#162](https://github.com/cccteam/session/issues/162)) ([512152f](https://github.com/cccteam/session/commit/512152f2b9a5864eb8f93fd76b28d2bdb7d10686))
* Expose methods to extract ID from context ([#155](https://github.com/cccteam/session/issues/155)) ([167a9fc](https://github.com/cccteam/session/commit/167a9fc4b6fe631bd3ff6f3f2d540fa65717bfd9))
* Modify cookie.Handler interface to always return an error in preparation for replacing securecookie package ([#159](https://github.com/cccteam/session/issues/159)) ([c21f645](https://github.com/cccteam/session/commit/c21f64517bd6168f10c51493071e1d7b7be43aa8))
* Remove access to internal implementation methods ([#157](https://github.com/cccteam/session/issues/157)) ([060bbca](https://github.com/cccteam/session/commit/060bbca24f1098358de014bb855f7785b806f9cb))


### Code Cleanup

* Cleanup error reporting ([#164](https://github.com/cccteam/session/issues/164)) ([af2ca26](https://github.com/cccteam/session/commit/af2ca260e1b40693c3e2e64bf8bb7530411b7d54))


### Code Upgrade

* Bump the go-dependencies group across 1 directory with 7 updates ([#163](https://github.com/cccteam/session/issues/163)) ([a52ee48](https://github.com/cccteam/session/commit/a52ee48e6c457741c7f6d08b32f5fa09925db126))

## [0.6.2](https://github.com/cccteam/session/compare/v0.6.1...v0.6.2) (2025-12-11)


### Features

* Implementation for user management ([#141](https://github.com/cccteam/session/issues/141)) ([67d8368](https://github.com/cccteam/session/commit/67d8368b4fd7b957068f8dedf2ccccca217fd2ca))


### Code Upgrade

* Bump the go-dependencies group with 2 updates ([#150](https://github.com/cccteam/session/issues/150)) ([ff055ef](https://github.com/cccteam/session/commit/ff055ef0827723e622982a5efd10cd75dfd27859))

## [0.6.1](https://github.com/cccteam/session/compare/v0.6.0...v0.6.1) (2025-12-08)


### Features

* Implement handlers for password authentication ([#134](https://github.com/cccteam/session/issues/134)) ([e5822ef](https://github.com/cccteam/session/commit/e5822ef28cfa7abb84db7ad4c367659d8484e764))


### Bug Fixes

* Fix UserInfo storage in context. ([#142](https://github.com/cccteam/session/issues/142)) ([ff3b1b4](https://github.com/cccteam/session/commit/ff3b1b4865f727656d45443be12dc22344ed71c4))


### Code Refactoring

* Aligned spanner and postgres implementations ([#133](https://github.com/cccteam/session/issues/133)) ([a90d4a8](https://github.com/cccteam/session/commit/a90d4a8b559904ad1748a3d05b309ac30db9aa72))
* Consolidated duplicate storage implementations into one ([#133](https://github.com/cccteam/session/issues/133)) ([a90d4a8](https://github.com/cccteam/session/commit/a90d4a8b559904ad1748a3d05b309ac30db9aa72))


### Code Cleanup

* Logging cleanup ([#133](https://github.com/cccteam/session/issues/133)) ([a90d4a8](https://github.com/cccteam/session/commit/a90d4a8b559904ad1748a3d05b309ac30db9aa72))
* Misc cleanup ([#133](https://github.com/cccteam/session/issues/133)) ([a90d4a8](https://github.com/cccteam/session/commit/a90d4a8b559904ad1748a3d05b309ac30db9aa72))


### Code Upgrade

* Bump the github-actions group with 3 updates ([#143](https://github.com/cccteam/session/issues/143)) ([b152043](https://github.com/cccteam/session/commit/b152043baf9bd914e7c7ddda715287154851e0c3))
* Bump the go-dependencies group across 1 directory with 4 updates ([#146](https://github.com/cccteam/session/issues/146)) ([d56b84f](https://github.com/cccteam/session/commit/d56b84f673b9a0ebce6a497fd48139fe22cb3055))

## [0.6.0](https://github.com/cccteam/session/compare/v0.5.9...v0.6.0) (2025-11-14)


### ⚠ BREAKING CHANGES

* Breaking change to session.NewOIDCAzure() as parameters have changed ([#131](https://github.com/cccteam/session/issues/131))
* Breaking change to session.NewPreauth() as parameters have changed ([#131](https://github.com/cccteam/session/issues/131))
* Removed SetSessionTimeout() handler since it is no longer needed ([#131](https://github.com/cccteam/session/issues/131))
* Remove permissions from session ([#130](https://github.com/cccteam/session/issues/130))

### Features

* Remove permissions from session ([#130](https://github.com/cccteam/session/issues/130)) ([597ef98](https://github.com/cccteam/session/commit/597ef98538d489ebd481e2b1413ba72dbdf41e61))


### Bug Fixes

* Correct CK_SessionsOidcSid constraint ([#115](https://github.com/cccteam/session/issues/115)) ([31618e0](https://github.com/cccteam/session/commit/31618e01bbee0bc3604e91a74d26988d5714b48a))
* Fixed bug in session.PreAuth.NewSession() where it set sameSiteStrict=false ([#131](https://github.com/cccteam/session/issues/131)) ([effd7ce](https://github.com/cccteam/session/commit/effd7ce9d5357b2f4aec2dfd922653a5bbda1752))


### Code Refactoring

* Breaking change to session.NewOIDCAzure() as parameters have changed ([#131](https://github.com/cccteam/session/issues/131)) ([effd7ce](https://github.com/cccteam/session/commit/effd7ce9d5357b2f4aec2dfd922653a5bbda1752))
* Breaking change to session.NewPreauth() as parameters have changed ([#131](https://github.com/cccteam/session/issues/131)) ([effd7ce](https://github.com/cccteam/session/commit/effd7ce9d5357b2f4aec2dfd922653a5bbda1752))
* Massive refactor to make package easier to maintain and use ([#131](https://github.com/cccteam/session/issues/131)) ([effd7ce](https://github.com/cccteam/session/commit/effd7ce9d5357b2f4aec2dfd922653a5bbda1752))
* Removed SetSessionTimeout() handler since it is no longer needed ([#131](https://github.com/cccteam/session/issues/131)) ([effd7ce](https://github.com/cccteam/session/commit/effd7ce9d5357b2f4aec2dfd922653a5bbda1752))


### Code Upgrade

* Bump cccteam/github-workflows/.github/workflows/golang-security-scan.yml from 5.6.0 to 5.14.0 in the github-actions group across 1 directory ([#127](https://github.com/cccteam/session/issues/127)) ([e1e37c2](https://github.com/cccteam/session/commit/e1e37c207988873e318be5aa77647553fdd1a4a7))
* Bump the go-dependencies group across 1 directory with 5 updates ([#132](https://github.com/cccteam/session/issues/132)) ([d497acd](https://github.com/cccteam/session/commit/d497acd587af7afb76341370b6e3e58d74a3b913))

## [0.5.9](https://github.com/cccteam/session/compare/v0.5.8...v0.5.9) (2025-10-03)


### Bug Fixes

* Add SameSite Strict to XSRF cookie ([#117](https://github.com/cccteam/session/issues/117)) ([09a139f](https://github.com/cccteam/session/commit/09a139f6b5c784d629fd581163c9c68f3964b7d1))
* Fix release please ([#118](https://github.com/cccteam/session/issues/118)) ([8b59b86](https://github.com/cccteam/session/commit/8b59b8652dfe2a29d7b363c3e338d8bec3af8d00))


### Code Upgrade

* Upgrade go dependencies, ci workflows, and linter ([#120](https://github.com/cccteam/session/issues/120)) ([774f7ed](https://github.com/cccteam/session/commit/774f7ed2904a4711715f8d8eca012441608ad745))

## [0.5.8](https://github.com/cccteam/session/compare/v0.5.7...v0.5.8) (2025-08-01)


### Features

* Add cookie options for more control over cookie configuration ([e57c483](https://github.com/cccteam/session/commit/e57c483776b97729993262a9cb891a459df3e84f))


### Bug Fixes

* Revert braking changes to public interface ([e57c483](https://github.com/cccteam/session/commit/e57c483776b97729993262a9cb891a459df3e84f))

## [0.5.7](https://github.com/cccteam/session/compare/v0.5.6...v0.5.7) (2025-07-25)


### Features

* Allow for Cookie Name and Domain  ([#104](https://github.com/cccteam/session/issues/104)) ([21061c5](https://github.com/cccteam/session/commit/21061c549d442fa6a5aa58497b394176d86094dc))

## [0.5.6](https://github.com/cccteam/session/compare/v0.5.5...v0.5.6) (2025-07-24)


### Features

* Specify Domain in Cookie Writing ([#102](https://github.com/cccteam/session/issues/102)) ([90dce3d](https://github.com/cccteam/session/commit/90dce3dee58f34af1396c0e6fba5b8b8d562ed41))

## [0.5.5](https://github.com/cccteam/session/compare/v0.5.4...v0.5.5) (2025-05-22)


### Code Upgrade

* Bump cccteam/github-workflows from 5.2.0 to 5.5.1 in the github-actions group ([#86](https://github.com/cccteam/session/issues/86)) ([9554665](https://github.com/cccteam/session/commit/955466524c41ae1d7be786eb2b747792689594c2))
* Update go and go deps ([#90](https://github.com/cccteam/session/issues/90)) ([f5a9502](https://github.com/cccteam/session/commit/f5a9502607a9e699e1b5d060db06a65d934e6b19))

## [0.5.4](https://github.com/cccteam/session/compare/v0.5.3...v0.5.4) (2025-05-12)


### Bug Fixes

* Update go and security scan frequency ([#84](https://github.com/cccteam/session/issues/84)) ([f6c0f52](https://github.com/cccteam/session/commit/f6c0f5260049b0eca99c556b2f5785142ca94546))

## [0.5.3](https://github.com/cccteam/session/compare/v0.5.2...v0.5.3) (2025-02-12)


### Code Upgrade

* go dependencies ([#70](https://github.com/cccteam/session/issues/70)) ([d80c65a](https://github.com/cccteam/session/commit/d80c65ae48a1c6a483cc71ea3c4ade1a73b1ba4a))

## [0.5.2](https://github.com/cccteam/session/compare/v0.5.1...v0.5.2) (2025-02-04)


### Code Upgrade

* Bump the go-dependencies group across 1 directory with 3 updates ([#66](https://github.com/cccteam/session/issues/66)) ([de68f06](https://github.com/cccteam/session/commit/de68f067bfae43a4a5692cbcc5a70b56c6285cd1))
* Upgrade to go1.23.5 to resolve GO-2025-3420 & GO-2025-3373 ([#65](https://github.com/cccteam/session/issues/65)) ([ef47705](https://github.com/cccteam/session/commit/ef47705d8964158dba238ae1b90e716c9f831f8c))

## [0.5.1](https://github.com/cccteam/session/compare/v0.5.0...v0.5.1) (2024-12-31)


### Bug Fixes

* Fix skipAuth implementation for lazy initialization change ([#57](https://github.com/cccteam/session/issues/57)) ([b1083e0](https://github.com/cccteam/session/commit/b1083e077281e09164bd8b6e4c1c4c875ce85525))

## [0.5.0](https://github.com/cccteam/session/compare/v0.4.3...v0.5.0) (2024-12-31)


### ⚠ BREAKING CHANGES

* `oidc.New()` no longer returns an error

### Features

* `oidc.New()` no longer returns an error ([c1800a4](https://github.com/cccteam/session/commit/c1800a4387105dfed42237548ecbbad8161436d4))
* Add timeouts to OIDC calls ([#56](https://github.com/cccteam/session/issues/56)) ([57182b0](https://github.com/cccteam/session/commit/57182b011bf46d98c4a9418257648b3f592458eb))
* Change initialization of OIDC to lazy load ([c1800a4](https://github.com/cccteam/session/commit/c1800a4387105dfed42237548ecbbad8161436d4))


### Code Upgrade

* Bump the go-dependencies group with 2 updates ([#53](https://github.com/cccteam/session/issues/53)) ([492f955](https://github.com/cccteam/session/commit/492f955b80d493a414378e52588cc897533e7aba))
* Update go version and dependencies ([#55](https://github.com/cccteam/session/issues/55)) ([44371ad](https://github.com/cccteam/session/commit/44371ad1a25fb1e845f7efdd78f1e7fdab388c66))

## [0.4.3](https://github.com/cccteam/session/compare/v0.4.2...v0.4.3) (2024-12-17)


### Dependencies

* Update dependencies ([#50](https://github.com/cccteam/session/issues/50)) ([d7e92a0](https://github.com/cccteam/session/commit/d7e92a0d8d302298726c06bed6f974f1e942d716))

## [0.4.2](https://github.com/cccteam/session/compare/v0.4.1...v0.4.2) (2024-12-11)


### Features

* Implement ability to control the Login URL used if error occurs during OIDC Callback processing ([#44](https://github.com/cccteam/session/issues/44)) ([98b9c12](https://github.com/cccteam/session/commit/98b9c12155c8daf60ec19664ae951735adefaa54))

## [0.4.1](https://github.com/cccteam/session/compare/v0.4.0...v0.4.1) (2024-11-15)


### Code Refactoring

* Refactor session storage to decouple oidc from non-oidc ([#38](https://github.com/cccteam/session/issues/38)) ([8efc963](https://github.com/cccteam/session/commit/8efc96333d7bad42da349bddb4ac1902413e5956))

## [0.4.0](https://github.com/cccteam/session/compare/v0.3.1...v0.4.0) (2024-10-24)


### ⚠ BREAKING CHANGES

* Remove unused UserManager parameter from the SessionStorage implementation constructors ([#31](https://github.com/cccteam/session/issues/31))
* Renamed SessionManager to SessionStorage. This impacted public constructors ([#31](https://github.com/cccteam/session/issues/31))

### Features

* Pre Authenticated Sessions ([#31](https://github.com/cccteam/session/issues/31)) ([e802ad6](https://github.com/cccteam/session/commit/e802ad6379adb2f43524867816a01e779bc58b10))


### Bug Fixes

* Fix incorrect logic when setting XSRF Token Cookie, which would return an error if the cookie didn't need to be set ([#33](https://github.com/cccteam/session/issues/33)) ([49741de](https://github.com/cccteam/session/commit/49741deb0a39d2508a791a449a41cd831d84bda7))
* Remove unused UserManager parameter from the SessionStorage implementation constructors ([#31](https://github.com/cccteam/session/issues/31)) ([e802ad6](https://github.com/cccteam/session/commit/e802ad6379adb2f43524867816a01e779bc58b10))


### Code Refactoring

* Renamed SessionManager to SessionStorage. This impacted public constructors ([#31](https://github.com/cccteam/session/issues/31)) ([e802ad6](https://github.com/cccteam/session/commit/e802ad6379adb2f43524867816a01e779bc58b10))


### Code Upgrade

* Update dependencies and fix tests ([#32](https://github.com/cccteam/session/issues/32)) ([1ff7d83](https://github.com/cccteam/session/commit/1ff7d839e64270b046faa087ef85fc4e885bc8e3))

## [0.3.1](https://github.com/cccteam/session/compare/v0.3.0...v0.3.1) (2024-10-08)


### Performance Improvements

* Reduce unneeded calls to UserPermissions() ([#28](https://github.com/cccteam/session/issues/28)) ([cd6846c](https://github.com/cccteam/session/commit/cd6846c7f8d2071100e16a0e06603249839d6be0))

## [0.3.0](https://github.com/cccteam/session/compare/v0.2.2...v0.3.0) (2024-10-07)


### ⚠ BREAKING CHANGES

* Authenticated Handler changed the structure of returned permissions

### Features

* Authenticated Handler changed the structure of returned permissions ([6c6c182](https://github.com/cccteam/session/commit/6c6c182ef0b50ab53de52c0d48f097200c930bf5))
* Return the UserPermissionCollection from the Authenticated Handler ([6c6c182](https://github.com/cccteam/session/commit/6c6c182ef0b50ab53de52c0d48f097200c930bf5))

## [0.2.2](https://github.com/cccteam/session/compare/v0.2.1...v0.2.2) (2024-10-07)


### Bug Fixes

* Add missing interface methods ([#24](https://github.com/cccteam/session/issues/24)) ([3662916](https://github.com/cccteam/session/commit/3662916e731ea424e0caf6c5758dff912eb6b8f7))

## [0.2.1](https://github.com/cccteam/session/compare/v0.2.0...v0.2.1) (2024-09-17)


### Features

* Add logging of addition and removal of roles([#17](https://github.com/cccteam/session/issues/17)) ([0cdfca9](https://github.com/cccteam/session/commit/0cdfca98bce254e23e4faa160d0fa48958c47411))
* Implement insecurecookie build tag to support development tooling ([#17](https://github.com/cccteam/session/issues/17)) ([0cdfca9](https://github.com/cccteam/session/commit/0cdfca98bce254e23e4faa160d0fa48958c47411))


### Code Upgrade

* Bump cccteam/github-workflows from 5.1.0 to 5.2.0 in the github-actions group ([#13](https://github.com/cccteam/session/issues/13)) ([3f846c8](https://github.com/cccteam/session/commit/3f846c855065efba2eb65cb076389143dca404b7))

## [0.2.0](https://github.com/cccteam/session/compare/v0.1.2...v0.2.0) (2024-09-11)


### ⚠ BREAKING CHANGES

* Fix breaking changes from access ([#14](https://github.com/cccteam/session/issues/14))

### Code Refactoring

* Fix breaking changes from access ([#14](https://github.com/cccteam/session/issues/14)) ([01cfe4b](https://github.com/cccteam/session/commit/01cfe4b8000b223f43c002150fe9d17484fd0296))

## [0.1.2](https://github.com/cccteam/session/compare/v0.1.1...v0.1.2) (2024-08-30)


### Features

* Implement Spanner support ([#8](https://github.com/cccteam/session/issues/8)) ([1aa8e47](https://github.com/cccteam/session/commit/1aa8e47fb46dce2bf0ac4f980d947d60f0a99e86))

## [0.1.1](https://github.com/cccteam/session/compare/v0.1.0...v0.1.1) (2024-08-27)


### Features

* Initial release ([#7](https://github.com/cccteam/session/issues/7)) ([eba19b4](https://github.com/cccteam/session/commit/eba19b4c1f799f1367cf254d3924d467d45e0466))


### Bug Fixes

* Fix workflow upgrade issue ([#2](https://github.com/cccteam/session/issues/2)) ([0e1fa74](https://github.com/cccteam/session/commit/0e1fa749bcfe4bb32ac308a1f0e7a2d7dfe4c5f3))


### Code Upgrade

* Bump cccteam/github-workflows from 4.1.0 to 5.0.0 in the github-actions group ([#1](https://github.com/cccteam/session/issues/1)) ([5dd538e](https://github.com/cccteam/session/commit/5dd538e050f21183f066c521d2b7215c28e6ce66))

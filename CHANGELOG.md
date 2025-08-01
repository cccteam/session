# Changelog

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

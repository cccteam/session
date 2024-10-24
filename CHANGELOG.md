# Changelog

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

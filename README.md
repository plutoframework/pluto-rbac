<p align="center">
  <img src="https://raw.githubusercontent.com/plutoframework/pluto/main/assets/readme/banner.svg" alt="Pluto — a small framework, wide open possibilities" width="100%" />
</p>

# Pluto RBAC

Named roles. Explicit permissions. Default deny.

[Website](https://plutoframework.github.io/pluto-site/) · [Documentation](https://plutoframework.github.io/pluto-site/docs/backend/rbac/) · [CLI demo](https://github.com/plutoframework/pluto/blob/main/docs/DEMO.md) · [First issues](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks)

## What you get

- Compile an immutable policy with named, described roles and capabilities.
- Resolve trusted assignments in an explicit subject and tenant scope.
- Keep identity, resource ownership and persistence outside the policy engine.

## Get started

### 1. Install

From a Go **1.25.5+** module:

```sh
go get github.com/plutoframework/pluto-rbac@v0.1.0
```

The runtime has **zero third-party dependencies**.

### 2. Run the purchasing example

```sh
git clone https://github.com/plutoframework/pluto-rbac.git
cd pluto-rbac
go run ./examples/purchasing
```

The example declares a catalog, compiles policy and evaluates scoped assignments.
Read [the source](examples/purchasing/main.go) alongside its output.

### 3. Add policy to your operations

Build the policy once at application startup. Inject trusted role resolution and
check permissions in application operations, including calls outside HTTP. Use
`policy.Roles()` and `policy.Permissions()` for catalog metadata in an admin UI.
Never accept role grants from the browser or treat tenant selection as membership.

## Read further

- [API and integration reference](docs/REFERENCE.md)
- [Field guide](https://plutoframework.github.io/pluto-site/docs/backend/rbac/)
- [Pluto ecosystem](https://github.com/plutoframework/pluto#the-ecosystem)

## Boundaries

Unknown roles invalidate the entire assignment. Policies do not authenticate users or decide resource ownership. Revocation/freshness belongs to the assignment resolver.

## Contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then choose a [good first issue](https://github.com/plutoframework/pluto/blob/main/CONTRIBUTING.md#starter-tasks).

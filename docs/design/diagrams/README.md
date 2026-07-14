# Diagrams

PlantUML source (`.puml`) for the thesis's UML design diagrams, flat in this
directory. Each filename is numbered in the intended reading order and
carries its category in the name (`NN-category-name.puml`), so a plain `ls`
sorts the diagrams the way they're meant to be read.  
Rendered output lives in `rendered/`, one `.svg` per `.puml`, same filename.

`_style.puml` holds the shared skinparam theme; every diagram includes it
with `!include _style.puml`. It is not itself a diagram and is skipped by
`make diagrams`.

The `rendered/*.svg` files are committed to the repo, so anyone browsing
on GitHub sees the diagrams without installing anything.

## Structure

```
diagrams/
├── _style.puml                                shared skinparam theme
├── 00-usecases-overview.puml                  UML use case diagram
├── 01-architecture-container.puml             container diagram
├── 02-architecture-deployment.puml            deployment diagram
├── 03-usecases-sequence-uc01-registration.puml
├── 04-usecases-sequence-uc02-login.puml
├── 05-usecases-sequence-uc03-backup.puml       sequence diagram per use case
├── 06-data-er-database-vault.puml             entity-relationship diagram
├── 07-data-filesystem-storage.puml            filesystem/storage layout
├── 08-security-pki-hierarchy.puml             PKI hierarchy
├── 09-security-trust-zones.puml               trust zones
├── 10-operations-state-acl-grant.puml         ACL grant state diagram
├── 11-operations-metrics-flow.puml            metrics flow
└── rendered/                                   same flat layout, one .svg per .puml
```

The numeric prefix reflects a system-comprehension reading order (not
folder-grouping); only diagrams that already exist are listed above (see the
project root `docs/design/README.md` for the full roadmap).

## Regenerating

Rendering happens in Docker: no local Java or Graphviz needed. After
editing a `.puml` file, from the project root run:

```bash
make diagrams
```

This rewrites every `rendered/NN-name.svg` to match its `.puml` source.
Commit the `.puml` and its regenerated `.svg` together.

## Adding a new diagram

1. Create `NN-category-name.puml` directly in this directory, following the
   existing reading order, starting with `!include _style.puml`
2. Run `make diagrams`
3. Commit the `.puml` and its generated `.svg` together

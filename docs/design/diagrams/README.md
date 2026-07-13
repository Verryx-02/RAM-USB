# Diagrams

PlantUML source (`.puml`) for the thesis's UML design diagrams, grouped into
subfolders by kind.  
Rendered output lives in `rendered/`, mirroring the same
subfolder layout.

`_style.puml` holds the shared skinparam theme; every diagram includes it
with `!include ../_style.puml` (one level up, since diagrams live in a
subfolder). It is not itself a diagram and is skipped by `make diagrams`.

The `rendered/**/*.svg` files are committed to the repo, so anyone browsing
on GitHub sees the diagrams without installing anything.

## Structure

```
diagrams/
├── _style.puml
├── use-cases/          UML use case diagram + one sequence diagram per use case
│   ├── 00-use-cases.puml
│   ├── 03-sequence-uc01-registration.puml
│   ├── 04-sequence-uc02-login.puml
│   └── 05-sequence-uc03-backup.puml
├── architecture/        container, deployment
│   ├── 01-container.puml
│   └── 02-deployment.puml
├── data/                 ER, filesystem/storage layout
│   ├── 06-er-database-vault.puml
│   └── 07-filesystem-storage.puml
├── security/             PKI hierarchy, trust zones
│   ├── 08-pki-hierarchy.puml
│   └── 09-trust-zones.puml
├── operations/           ACL grant state, metrics flow
│   ├── 10-state-acl-grant.puml
│   └── 11-metrics-flow.puml
└── rendered/             same subfolders, one .svg per .puml
```

Only the subfolders that currently hold a diagram exist in the repo;
the rest above are the planned homes for the diagrams still to be written
(see the project root `docs/design/README.md` for the full roadmap).
Create a subfolder when its first diagram is added.

## Regenerating

Rendering happens in Docker: no local Java or Graphviz needed. After
editing a `.puml` file, from the project root run:

```bash
make diagrams
```

This walks every subfolder and rewrites `rendered/<subfolder>/NN-name.svg`
to match its `.puml` source. Commit the `.puml` and its regenerated `.svg`
together.

## Adding a new diagram

1. Pick the subfolder matching its kind (create it if it doesn't exist yet)
2. Create `NN-name.puml` there, starting with `!include ../_style.puml`
3. Run `make diagrams`
4. Commit the `.puml` and its generated `.svg` together

# Diagrams

UML diagrams for RAM-USB, written in PlantUML. 
Source files are `.puml`; 
rendered `.svg` files are committed alongside them so anyone browsing the repo sees the diagrams without installing anything.

## Structure

Diagrams are flat in `diagrams/`, numbered in the intended reading order
with the category folded into each filename (`NN-category-name.puml`), so a
plain directory listing sorts diagrams the way they're meant to be read.
Rendered SVGs are mirrored under `rendered/` with the same flat layout:

```
diagrams/
├── _style.puml                                shared skinparam theme, included by every diagram
├── 00-usecases-overview.puml
├── 01-architecture-container.puml
├── 02-architecture-deployment.puml
├── 03-usecases-sequence-uc01-registration.puml
├── 04-usecases-sequence-uc02-login.puml
├── 05-usecases-sequence-uc03-backup.puml
├── 06-data-er-database-vault.puml
├── 07-data-filesystem-storage.puml
├── 08-security-pki-hierarchy.puml
├── 09-security-trust-zones.puml
├── 10-operations-state-acl-grant.puml
├── 11-operations-metrics-flow.puml
└── rendered/                                   same flat layout, one .svg per .puml
```

Only diagrams that currently exist are listed above; the numeric prefix
reflects a system-comprehension reading order, not folder-grouping.

## Reading the diagrams

Just open the `.svg` files, or view them inline on GitHub.

## Regenerating a diagram

After editing any `.puml` file, regenerate the SVGs with Docker:

```bash
make diagrams
```

This runs PlantUML in a container and rewrites every `.svg` to match its `.puml` source. Commit both together.

## Adding a new diagram

1. Pick the subfolder matching its kind (create it if it doesn't exist yet)
2. Create `NN-name.puml` there, starting with `!include ../_style.puml`
3. Run `make diagrams`
4. Commit the `.puml` and its generated `.svg` together
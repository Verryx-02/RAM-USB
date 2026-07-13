# Diagrams

UML diagrams for RAM-USB, written in PlantUML. 
Source files are `.puml`; 
rendered `.svg` files are committed alongside them so anyone browsing the repo sees the diagrams without installing anything.

## Structure

Diagrams are grouped into subfolders by kind, with rendered SVGs mirrored
under `rendered/`:

```
diagrams/
├── _style.puml                    shared skinparam theme, included by every diagram
├── use-cases/
│   ├── 00-use-cases.puml
│   ├── 03-sequence-uc01-registration.puml
│   ├── 04-sequence-uc02-login.puml
│   └── 05-sequence-uc03-backup.puml
├── architecture/
│   ├── 01-container.puml
│   └── 02-deployment.puml
├── data/
│   ├── 06-er-database-vault.puml
│   └── 07-filesystem-storage.puml
├── security/
│   ├── 08-pki-hierarchy.puml
│   └── 09-trust-zones.puml
├── operations/
│   ├── 10-state-acl-grant.puml
│   └── 11-metrics-flow.puml
└── rendered/                      same subfolders, one .svg per .puml
```

Only the subfolders holding an existing diagram exist in the repo today;
the others are created as their first diagram is added.

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
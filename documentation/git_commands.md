# Create a new branch (and switch to it (aka. setting it as the current working branch))
```bash
git checkout -b <branch-name>
```
Same as
```bash
git branch <branch-name>
git checkout <branch-name>
```
**Ex.**
```bash
git checkout -b dev/riccardo
```
Same as
```bash
git branch dev/riccardo
git checkout dev/riccardo 
```
The first time I have to work on the project I have to create my development branch

<br><br><br>

# Regular update of the branch you want to work on
```bash
git chechout <source-branch-name>
git pull <source-branch-name>
git checkout <branch-name>
git rebase <source-branch-name>
```
**Ex.**
```bash
git checkout main
git pull
git checkout dev/riccardo
git rebase main
```
Before working on new feature in my personal development baranch (that I've just swithced to)
I make sure to have the fresh stuff from the main branch
- Switch to `main`
- Acquire "fresh stuff" from the remote `main`
- Switch to `dev/riccardo`
- Acquire "the fresh stuff" from `main`

<br><br><br>

# Merge changes you did in a branch to another branch
```bash
git checkout <target-branch-name>
git merge <source-branch-name>
```
**Ex.**
```bash
git checkout main
git merge dev/riccardo
```
Merging changes from your development branch to the main one
- Switch to the `main` branch
- Merge from `dev/riccardo`

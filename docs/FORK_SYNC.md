# Fork Sync Model

- `origin` -> your fork
- `upstream` -> `infosave2007/aivpn`
- local branch `main` mirrors `upstream/master`
- product branch `our-prod` holds custom work

## Update flow

```bash
git checkout main
git fetch upstream
git merge --ff-only upstream/master
git push origin main

git checkout our-prod
git merge main
# resolve conflicts if needed
git push origin our-prod
```

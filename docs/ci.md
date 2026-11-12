# Continuous integration

Two workflows run on every push:

| Workflow | Where | What |
|---|---|---|
| `host` (`.github/workflows/host.yml`) | GitHub-hosted macOS | `make test`, `make asan`, a short `make fuzz` |
| `powerpc` (`.github/workflows/vm.yml`) | the maintainer's self-hosted runner | `tools/vm-test.sh leopard` (PowerPC build, full suite, release, constant-time and app checks) and `tools/vm-test.sh tiger` |

`host` also runs for pull requests. `powerpc` never does: a self-hosted runner must not run code from forks. It runs only for pushes to this repository, release tags and manual runs.

## Why a self-hosted runner

The shipping binaries need gcc-4.0 and the Mac OS X 10.4u SDK, which only exist on the emulated Leopard VM. GitHub's runner program cannot run on PowerPC Mac OS X, so a small Linux container on the maintainer's Mac runs it and drives the VMs over SSH, exactly as a person running `tools/vm-test.sh` would.

## The container

`ci/runner/` holds the image (Debian slim plus the GitHub runner for linux/arm64, pinned by version and SHA-256), its start script and a compose file.

- The container sees the VMs only through their forwarded SSH ports (`host.docker.internal:2222` and `:2223`).
- It mounts one folder read-only: an SSH config and a key used by CI alone. Nothing else from the Mac is mounted.
- The registration is kept in a Docker volume, so a registration token is needed only on the first start.
- CI builds in `~/tsppc-ci` on the VMs (`TSPPC_VM_DIR`), never in the folder used for builds made by hand.
- Jobs run one at a time (`concurrency: powerpc-vms`).

The runner is persistent, not ephemeral: an ephemeral runner needs a fresh registration token for every job, which would mean keeping a repository-admin token inside the container that runs the jobs. Since only pushes by people with write access reach it, a persistent runner is the smaller risk.

## Setting it up

1. Make a key for CI and authorize it on both VMs (on the VMs' login, in `~/.ssh/authorized_keys`):

   ```
   mkdir -p ~/.tsppc-runner/ssh && chmod 700 ~/.tsppc-runner/ssh
   ssh-keygen -t rsa -b 3072 -N '' -C tsppc-ci -f ~/.tsppc-runner/ssh/id_vm
   ```

2. Copy `ci/runner/ssh_config.example` to `~/.tsppc-runner/ssh/config` and set `User`.
3. In the repository's settings: Actions, Runners, New self-hosted runner. Copy the registration token (it is valid for an hour). Also set Actions, General, "Require approval for all external contributors".
4. Start it:

   ```
   REPO_URL=https://github.com/<owner>/<repo> RUNNER_TOKEN=<token> \
   TSPPC_RUNNER_SSH=$HOME/.tsppc-runner/ssh \
   docker compose -f ci/runner/compose.yml up -d --build
   ```

   Later starts need only `TSPPC_RUNNER_SSH`. The container restarts with Docker Desktop.

The VMs and UTM must be running for `powerpc` jobs; otherwise the job waits for the runner or fails at SSH.

## Removing it

`docker compose -f ci/runner/compose.yml down -v`, remove the runner in the repository's settings, and delete the `tsppc-ci` key line from the VMs' `authorized_keys`.

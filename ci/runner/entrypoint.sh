#!/bin/sh
# Start the runner. The first start registers it with RUNNER_TOKEN (a one-time
# registration token) and keeps the registration in /home/runner/state (a
# volume), so later starts need no token.
set -eu

R=/home/runner/actions-runner
S=/home/runner/state
KEYS=/run/tsppc-ssh

# SSH: the config and key are mounted read-only; ssh wants them private.
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
cp "$KEYS/config" "$HOME/.ssh/config"
cp "$KEYS/id_vm" "$HOME/.ssh/id_vm"
chmod 600 "$HOME/.ssh/config" "$HOME/.ssh/id_vm"

cd "$R"
if [ -f "$S/.runner" ]; then
    cp -p "$S/.runner" "$S/.credentials" "$S/.credentials_rsaparams" "$R/"
else
    : "${REPO_URL:?set REPO_URL, e.g. https://github.com/<owner>/<repo>}"
    : "${RUNNER_TOKEN:?set RUNNER_TOKEN for the first start (repository settings, Actions, Runners, New self-hosted runner)}"
    ./config.sh --unattended --replace \
        --url "$REPO_URL" --token "$RUNNER_TOKEN" \
        --name "${RUNNER_NAME:-tsppc-vm-runner}" \
        --labels tsppc-vm --work _work
    cp -p .runner .credentials .credentials_rsaparams "$S/"
fi
unset RUNNER_TOKEN
exec ./run.sh

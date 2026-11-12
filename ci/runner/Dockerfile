# Self-hosted GitHub Actions runner that drives the PowerPC VMs over SSH.
# See docs/ci.md. Runs on the maintainer's Mac in Docker Desktop (linux/arm64).
FROM debian:bookworm-slim

ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256=670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client tar gzip \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1001 runner

WORKDIR /home/runner/actions-runner
RUN curl -fsSL -o /tmp/runner.tar.gz \
      "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-arm64-${RUNNER_VERSION}.tar.gz" \
 && echo "${RUNNER_SHA256}  /tmp/runner.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/runner.tar.gz \
 && rm /tmp/runner.tar.gz \
 && ./bin/installdependencies.sh \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /home/runner/state \
 && chown -R runner:runner /home/runner

COPY --chown=runner:runner entrypoint.sh /home/runner/entrypoint.sh
USER runner
ENTRYPOINT ["/bin/sh", "/home/runner/entrypoint.sh"]

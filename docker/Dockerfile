# Tüm tarama araçlarını içeren imaj — GitHub Actions'ın olmadığı ortamlar (fabrika ağı,
# yerel makine, GitLab/Jenkins) için. CI ile aynı scan.sh'i çalıştırır.
#
#   docker build -f docker/Dockerfile -t security-toolkit .
#   docker build -f docker/Dockerfile --build-arg WITH_DOTNET=true -t security-toolkit:dotnet .
#   docker run --rm -v "$PWD:/src" security-toolkit [--fail-on high] [--skip trivy]
FROM python:3.14-slim-bookworm@sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527

ARG WITH_DOTNET=false

ENV SECURITY_TOOLS_DIR=/opt/security-tools \
    PATH=/opt/security-tools/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && if [ "$WITH_DOTNET" = "true" ]; then apt-get install -y --no-install-recommends libicu72; fi \
 && rm -rf /var/lib/apt/lists/* \
 # Bağlanan repo farklı kullanıcıya ait olabilir
 && git config --system --add safe.directory '*'

COPY scripts/ /opt/security-toolkit/scripts/
COPY rules/ /opt/security-toolkit/rules/
COPY docker/entrypoint.sh /opt/security-toolkit/docker/entrypoint.sh

RUN extra=(); [ "$WITH_DOTNET" = "true" ] && extra+=(--with-dotnet); \
    bash /opt/security-toolkit/scripts/install-tools.sh "${extra[@]}" \
 && gitleaks version && osv-scanner --version && trivy --version && bandit --version && semgrep --version \
 && chmod +x /opt/security-toolkit/scripts/*.sh /opt/security-toolkit/docker/entrypoint.sh

# Trivy kural paketini imaja göm: çevrimdışı ortamlarda da yapılandırma taraması çalışsın (başarısızlık kritik değil)
RUN trivy config --quiet --format json /opt/security-toolkit/rules >/dev/null || echo "trivy kural paketi önceden indirilemedi"

WORKDIR /src
ENTRYPOINT ["/opt/security-toolkit/docker/entrypoint.sh"]

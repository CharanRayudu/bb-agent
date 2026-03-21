# mirage Security Tools Sandbox
# This image is used by the agent to execute security commands in isolation
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Core security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Reconnaissance
    nmap \
    masscan \
    amass \
    dnsutils \
    whois \
    # Web Testing
    nikto \
    gobuster \
    dirb \
    wfuzz \
    ffuf \
    sqlmap \
    hydra \
    seclists \
    wordlists \
    # Network
    netcat-openbsd \
    socat \
    curl \
    wget \
    tcpdump \
    net-tools \
    # Exploitation
    metasploit-framework \
    exploitdb \
    # Scripting & Utils
    python3 \
    python3-pip \
    python3-venv \
    jq \
    git \
    vim-tiny \
    iputils-ping \
    traceroute \
    unzip \
    python3-requests \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright for Headless Browser Orchestration
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/lib/playwright
RUN npm install -g playwright && \
    npx playwright install --with-deps chromium

# Install additional Python-based tools
RUN python3 -m pip install --break-system-packages \
    httpx-toolkit 2>/dev/null || true

# Install nuclei
RUN curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d : -f 2,3 | tr -d \" | xargs curl -sL -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm -f /tmp/nuclei.zip \
    && nuclei -ut

# Install subfinder
RUN curl -sL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d : -f 2,3 | tr -d \" | xargs curl -sL -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm -f /tmp/subfinder.zip

RUN set -eux; \
    DALFOX_URL="$(curl -fsSL https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r '.assets[] | select(.name == "dalfox-linux-amd64.tar.gz") | .browser_download_url')"; \
    test -n "$DALFOX_URL"; \
    curl -fsSL "$DALFOX_URL" -o /tmp/dalfox.tar.gz; \
    tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox-linux-amd64; \
    mv /usr/local/bin/dalfox-linux-amd64 /usr/local/bin/dalfox; \
    chmod +x /usr/local/bin/dalfox; \
    rm -f /tmp/dalfox.tar.gz

# Install advanced CLI security tools (separate steps to avoid cascade failures)
RUN cd /opt && \
    git clone --depth 1 https://github.com/commixproject/commix.git && \
    ln -sf /opt/commix/commix.py /usr/local/bin/commix

RUN cd /opt && \
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git && \
    cd XSStrike && pip3 install --break-system-packages -r requirements.txt && \
    ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /opt/XSStrike/xsstrike.py

RUN cd /opt && \
    git clone --depth 1 https://github.com/s0md3v/Corsy.git && \
    pip3 install --break-system-packages requests && \
    ln -sf /opt/Corsy/corsy.py /usr/local/bin/corsy

RUN cd /opt && \
    git clone --depth 1 https://github.com/epinna/tplmap.git && \
    pip3 install --break-system-packages -r /opt/tplmap/requirements.txt && \
    ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap || true

# Verify critical tools are installed
RUN echo "=== Tool Verification ===" && \
    which nmap && which ffuf && which gobuster && which sqlmap && \
    which nuclei && which subfinder && \
    (which dalfox || (ls -R /usr/local/bin | grep dalfox && exit 1)) && \
    which curl && which python3 && \
    (which xsstrike || echo "WARNING: xsstrike not found") && \
    (which commix || echo "WARNING: commix not found") && \
    nuclei -version && \
    echo "=== All critical tools OK ==="

# Working directory
WORKDIR /workspace

# Default shell
CMD ["/bin/bash"]

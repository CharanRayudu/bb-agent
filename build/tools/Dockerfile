# mirage Security Tools Sandbox
# This image is used by the agent to execute security commands in isolation
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV GOBIN=/usr/local/bin
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:/root/go/bin:/usr/local/bin:/usr/local/go/bin:$PATH

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
    python3-dev \
    jq \
    git \
    golang-go \
    rustc \
    cargo \
    build-essential \
    pkg-config \
    libpcap-dev \
    libssl-dev \
    ca-certificates \
    vim-tiny \
    iputils-ping \
    traceroute \
    unzip \
    python3-requests \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based tools into an isolated venv and expose wrapper binaries in PATH
RUN python3 -m venv /opt/venvs/security-tools && \
    /opt/venvs/security-tools/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venvs/security-tools/bin/pip install arjun

# Install ParamSpider and dirsearch from source for reproducible CLI wrappers
RUN mkdir -p /opt/security-tools && \
    cd /opt/security-tools && \
    git clone --depth 1 https://github.com/r0oth3x49/ghauri.git && \
    git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git && \
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git && \
    /opt/venvs/security-tools/bin/pip install -r /opt/security-tools/ghauri/requirements.txt && \
    /opt/venvs/security-tools/bin/pip install /opt/security-tools/ParamSpider && \
    /opt/venvs/security-tools/bin/pip install -r /opt/security-tools/dirsearch/requirements.txt

RUN printf '%s\n' '#!/bin/sh' 'exec /opt/venvs/security-tools/bin/arjun "$@"' > /usr/local/bin/arjun && \
    printf '%s\n' '#!/bin/sh' 'exec /opt/venvs/security-tools/bin/python /opt/security-tools/ghauri/ghauri.py "$@"' > /usr/local/bin/ghauri && \
    printf '%s\n' '#!/bin/sh' 'exec /opt/venvs/security-tools/bin/python /opt/security-tools/ParamSpider/paramspider.py "$@"' > /usr/local/bin/paramspider && \
    printf '%s\n' '#!/bin/sh' 'exec /opt/venvs/security-tools/bin/python /opt/security-tools/dirsearch/dirsearch.py "$@"' > /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/arjun /usr/local/bin/ghauri /usr/local/bin/paramspider /usr/local/bin/dirsearch

# Install massdns prerequisite for puredns
RUN cd /opt && \
    git clone --depth 1 https://github.com/blechschmidt/massdns.git && \
    cd massdns && \
    make && \
    make install

# Install nuclei
RUN curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d : -f 2,3 | tr -d \" | xargs curl -sL -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm -f /tmp/nuclei.zip \
    && nuclei -ut

# Install Go-based recon, probing, discovery, and helper tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/Emoe/kxss@latest && \
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

RUN set -eux; \
    DALFOX_URL="$(curl -fsSL https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r '.assets[] | select(.name == "dalfox-linux-amd64.tar.gz") | .browser_download_url')"; \
    test -n "$DALFOX_URL"; \
    curl -fsSL "$DALFOX_URL" -o /tmp/dalfox.tar.gz; \
    tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox-linux-amd64; \
    mv /usr/local/bin/dalfox-linux-amd64 /usr/local/bin/dalfox; \
    chmod +x /usr/local/bin/dalfox; \
    rm -f /tmp/dalfox.tar.gz

# Install Rust-based tools
RUN cargo install feroxbuster && \
    cargo install jwt-hack && \
    cargo install x8 && \
    ln -sf /root/.cargo/bin/feroxbuster /usr/local/bin/feroxbuster && \
    ln -sf /root/.cargo/bin/jwt-hack /usr/local/bin/jwt-hack && \
    ln -sf /root/.cargo/bin/x8 /usr/local/bin/x8

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
    (pip3 install --break-system-packages -r /opt/tplmap/requirements.txt || true) && \
    ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap

# Verify critical tools are installed
RUN echo "=== Tool Verification ===" && \
    which subfinder && which amass && which puredns && which waybackurls && which gau && \
    which naabu && which httpx && which hakrawler && which katana && \
    which feroxbuster && which gobuster && which ffuf && which dirsearch && \
    which arjun && which paramspider && which x8 && which qsreplace && which kxss && \
    which nuclei && which dalfox && which crlfuzz && which sqlmap && which ghauri && which commix && \
    which tplmap && which jsluice && which jwt-hack && which pdtm && \
    which nmap && which masscan && \
    (which dalfox || (ls -R /usr/local/bin | grep dalfox && exit 1)) && \
    which curl && which python3 && which massdns && \
    (which xsstrike || echo "WARNING: xsstrike not found") && \
    (which corsy || echo "WARNING: corsy not found") && \
    nuclei -version && \
    echo "=== All critical tools OK ==="

# Working directory
WORKDIR /workspace

# Default shell
CMD ["/bin/bash"]

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
    sqlmap \
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
    && rm -rf /var/lib/apt/lists/*

# Install additional Python-based tools
RUN python3 -m pip install --break-system-packages \
    httpx-toolkit 2>/dev/null || true

# Install nuclei
RUN curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d : -f 2,3 | tr -d \" | xargs curl -sL -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm -f /tmp/nuclei.zip

# Install subfinder
RUN curl -sL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d : -f 2,3 | tr -d \" | xargs curl -sL -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && rm -f /tmp/subfinder.zip

# Working directory
WORKDIR /workspace

# Default shell
CMD ["/bin/bash"]

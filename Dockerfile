# Use an official Ubuntu as a base image
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV NVM_DIR=/root/.nvm
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/tests
ENV DISPLAY=:99
ENV LIBGL_ALWAYS_INDIRECT=1

# Update package list and install basic utilities
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    tar \
    gzip \
    gnupg \
    openssh-client \
    xz-utils \
    patch \
    --no-install-recommends

# Install Python and related tools
RUN apt install software-properties-common -y && \
    add-apt-repository ppa:deadsnakes/ppa -y

RUN apt-get update && apt-get install -y \
    python3.12 \
    python3.12-venv \
    python3.12-dev \
    --no-install-recommends

# Install conda
RUN wget --quiet https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh -O /tmp/miniconda.sh \
    && bash /tmp/miniconda.sh -b -p /opt/conda \
    && rm -f /tmp/miniconda.sh \
    && /opt/conda/bin/conda clean -ya
ENV PATH="/opt/conda/bin:$PATH"

# Create testbed
RUN conda create -n testbed python=3.12

# Install browser dependencies
RUN apt-get install -y \
    chromium-browser \
    fonts-liberation \
    fonts-noto-color-emoji \
    libnss3-tools \
    libatk-bridge2.0-0 \
    libnss3 \
    libxcomposite1 \
    libxrandr2 \
    libxdamage1 \
    libxkbcommon0 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libgtk-3-0 \
    --no-install-recommends

# Install Xvfb and VNC tools
RUN apt-get install -y \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    --no-install-recommends

# Install bspwm supporting tools
RUN apt-get install -y \
    bspwm \
    feh \
    xterm \
    --no-install-recommends

# Install dependencies related to tests
RUN apt-get install -y \
    mkcert \
    watchman \
    python3-pyqt5 \
    ffmpeg \
    xclip \
    --no-install-recommends

# Install nginx, ruby, and pusher-fake
RUN apt-get install -y \
    nginx \
    --no-install-recommends
RUN gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB && \
    curl -sSL https://get.rvm.io | bash -s stable && \
    usermod -a -G rvm root
RUN bash -c 'source /etc/profile.d/rvm.sh && rvm install ruby 3.3.4'
RUN bash -c 'source /etc/profile.d/rvm.sh && gem install pusher:2.0.3 pusher-fake:6.0.0'

# Generate self-signed certificate with CN=pusher_proxy
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/pusher.key \
    -out /etc/nginx/ssl/pusher.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=ws-mt1.pusher.com"

# Clone the GitHub repository into /app/expensify
# RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts
RUN git clone https://github.com/Expensify/App.git /app/expensify --single-branch

# Install NVM and Node.js
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash && \
    . "$NVM_DIR/nvm.sh"

# Install Pip
COPY requirements.txt .
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3.12 get-pip.py && \
    python3.12 -m pip install --upgrade pip && \
    python3.12 -m pip install --no-cache-dir --ignore-installed -r requirements.txt

# Setup playwright
RUN python3.12 -m playwright install
RUN python3.12 -m playwright install-deps

# Copy bspwm configuration files
RUN mkdir -p /root/.config/bspwm
RUN echo '#!/bin/bash\nbspc monitor -d 1 2 3 4\nbspc config automatic_scheme spiral\nbspc config border_width 2\nbspc config window_gap 8' > /root/.config/bspwm/bspwmrc
RUN chmod +x /root/.config/bspwm/bspwmrc

# Create the /app/tests/ directory
RUN mkdir -p /app/tests

# Copy files into the /app/tests/ directory
COPY issues/ /app/tests/issues/
COPY utils/ /app/tests/utils/
COPY runtime_scripts/setup_expensify.yml /app/tests/setup_expensify.yml
COPY runtime_scripts/setup_mitmproxy.yml /app/tests/setup_mitmproxy.yml
COPY runtime_scripts/run_test.yml /app/tests/run_test.yml
COPY runtime_scripts/run_fixed_state.yml /app/tests/run_fixed_state.yml
COPY runtime_scripts/run_user_tool.yml /app/tests/run_user_tool.yml
COPY runtime_scripts/run_broken_state.yml /app/tests/run_broken_state.yml
COPY runtime_scripts/setup_eval.yml /app/tests/setup_eval.yml
COPY runtime_scripts/run.sh /app/tests/run.sh
COPY runtime_scripts/replay.py /app/tests/replay.py
COPY runtime_scripts/rewrite_test.py /app/tests/rewrite_test.py
COPY runtime_scripts/npm_fix.py /app/expensify/npm_fix.py
COPY runtime_scripts/pusher_nginx.conf /etc/nginx/nginx.conf
RUN chmod +x /app/tests/run.sh
WORKDIR /app/expensify

# Expose the NoVNC and VNC ports
EXPOSE 5901
EXPOSE 5900

# Create python alias
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1 && \
    update-alternatives --set python /usr/bin/python3

# Set the entrypoint and default command
ENTRYPOINT ["/bin/bash", "-l", "-c"]
CMD ["/app/tests/run.sh"]

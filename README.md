# Secure Docker API Access with Mutual TLS, Dummy Interface, and User Namespace Remapping

This guide outlines a highly secure method for managing your Docker daemon API, especially when you have containers (like Traefik) needing access on the same host. This approach leverages Docker's built-in security features and standard Linux networking tools to create a robust and isolated environment.

This setup combines:

* **User Namespace Remapping (`userns-remap`)**: To isolate container processes from host root privileges.
* **Dummy Network Interface**: To create a dedicated, isolated network endpoint for the Docker API on the local host.
* **Mutual TLS (mTLS)**: To ensure strong authentication and encryption for Docker API communication.
* **UFW (Uncomplicated Firewall)**: To enforce strict network access rules, explicitly blocking external connections to the Docker API.

## Why this setup?

By default, directly exposing the Docker API over TCP is unsecure. While `userns-remap` significantly enhances host security by remapping container `root` to an unprivileged user, it doesn't inherently secure the Docker API access point itself from other containers on the same host.

Directly mounting `/var/run/docker.sock` into containers (e.g., for Traefik to interact with the Docker daemon) can also be risky. If a container with `docker.sock` access is compromised, an attacker could potentially control your entire Docker daemon, launching malicious containers or impacting others.

This solution addresses these concerns by:

* **Eliminating Direct `docker.sock` Mounting**: Your Traefik container will connect to a TCP endpoint, not directly mount the Unix socket.
* **Isolating API Access**: The Docker API is bound to an isolated dummy interface, preventing external network exposure.
* **Enforcing Strict Authentication**: mTLS ensures only trusted clients (like Traefik, with its specific client certificate) can communicate with the Docker daemon.
* **Layered Defense**: Combining `userns-remap`, network isolation, mTLS, and firewall rules creates a robust security posture.

---

## 1. Install Docker

These steps guide you through installing Docker Engine on Ubuntu, following the [official Docker documentation](https://docs.docker.com/engine/install/ubuntu/).

### 1.1. Uninstall Conflicting Packages

Remove any existing Docker-related packages that might conflict with the new installation.

```bash
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
```

*Explanation*: This command iterates through common package names for Docker and related tools, ensuring any older or conflicting installations are removed to prevent issues during the new installation.

### 1.2. Install Docker

#### 1.2.1. Add Docker's Official APT Repository

Set up Docker's APT repository to ensure you install the latest official packages.

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```

*Explanation*: These commands first install necessary utilities (`ca-certificates`, `curl`), create a directory for APT keyrings, download Docker's GPG key, set appropriate permissions for the key, and then add the Docker APT repository to your system's sources list. Finally, `sudo apt-get update` refreshes your package list to include Docker packages.

#### 1.2.2. Install Docker Engine

Install the core Docker components.

```bash
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

*Explanation*: This command installs `docker-ce` (Docker Community Edition daemon), `docker-ce-cli` (the command-line client), `containerd.io` (the container runtime), `docker-buildx-plugin` (for enhanced build capabilities), and `docker-compose-plugin` (for managing multi-container Docker applications).

### 1.3. Verify Docker Installation

Test your Docker installation to ensure it's working correctly.

```bash
sudo docker run hello-world
```

*Explanation*: This command pulls and runs the `hello-world` Docker image. If successful, it prints a message confirming Docker is installed and running correctly, then exits.

---

## 2. Secure Docker

This section details how to secure your Docker environment using `userns-remap` for host isolation and mTLS for API access control.

### 2.1. Enable `userns-remap` (Rootless Container Isolation)

This configuration prevents privilege-escalation attacks by remapping the container's root user to a less-privileged user on the host.

> 💡 **Why?**
>
> The best way to prevent privilege-escalation attacks from within a container is to configure your container's applications to run as unprivileged users. For containers whose processes must run as the root user within the container, you can re-map this user to a less-privileged user on the Docker host. The mapped user is assigned a range of UIDs which function within the namespace as normal UIDs from 0 to 65536, but have no privileges on the host machine itself.
>
> See related [Docker documentation on User Namespace Remap](https://docs.docker.com/engine/security/userns-remap/).

#### 2.1.1. Check existing UID/GID mappings (Optional)

Before configuring, you can check if any `subuid` or `subgid` mappings already exist.

```bash
grep -E '^(root|dockremap)' /etc/subuid /etc/subgid
cat /etc/subuid
```

*Example Output*:
`myUser:100000:65536`
*Explanation*: These commands display entries in `/etc/subuid` and `/etc/subgid` which define ranges of UIDs and GIDs available for user namespaces. After `userns-remap` is enabled, Docker will typically add an entry for a `dockremap` user.

#### 2.1.2. Configure `/etc/docker/daemon.json`

Edit or create the Docker daemon configuration file.

```bash
sudo nano /etc/docker/daemon.json
```

Paste the following content:

```json
{
  "userns-remap": "default",
  "experimental": false,
  "storage-driver": "overlay2"
}
```

*Explanation*:

* `"userns-remap": "default"`: Instructs Docker to automatically create a `dockremap` user and manage the UID/GID remapping ranges.
* `"experimental": false`: Disables experimental Docker features.
* `"storage-driver": "overlay2"`: Specifies OverlayFS as the storage driver, which is the recommended and most efficient driver for most Linux distributions. See [Docker's OverlayFS documentation](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/) for more info.
* *Optional*: You can add `"log-driver": "journald"` for centralized logging with `systemd-journald`.

#### 2.1.3. Restart Docker

Apply the `userns-remap` configuration by restarting the Docker daemon.

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

*Explanation*: `daemon-reload` reloads the `systemd` manager configuration. `restart docker` stops and then starts the Docker daemon, applying the new `daemon.json` settings. Be aware that enabling `userns-remap` will cause all existing containers and images to become inaccessible and require rebuilding/re-pulling.

#### 2.1.4. Validate `userns-remap`

Verify that the `dockremap` user has been created and its details.

```bash
getent passwd dockremap
```

*Example Output*: `dockremap:x:997:985::/home/dockremap:/bin/sh`

```bash
id dockremap
```

*Example Output*: `uid=997(dockremap) gid=985(dockremap) grupos=985(dockremap)`
*Explanation*: These commands confirm the creation and details of the `dockremap` user, which Docker uses internally for user remapping. The UIDs and GIDs for `dockremap` might vary on your system.

---

### 2.2. Secure Docker API with mTLS

This section sets up secure, mutually authenticated communication for the Docker API using custom scripts and OpenSSL configuration files available in your repository.

#### 2.2.1. Prepare Directory Structure and Files

First, clone the [`docker_conf_m8`](https://github.com/mano8/docker_conf_m8) repository to `/opt/docker_conf_m8` to get the necessary scripts and configuration templates.

```bash
# Define the IP for your dummy interface (e.g., 10.254.254.1)
export DOCKER_HOST_IP="YOUR_DOCKER_HOST_IP_HERE" # <<< IMPORTANT: SET THIS!
BASE_DIR="/opt/docker_conf_m8"

# Clone the repository
sudo git clone https://github.com/mano8/docker_conf_m8.git "${BASE_DIR}"
sudo chmod 700 "${BASE_DIR}" # Secure base directory
```

*Explanation*: This sets up your base directory and clones the `docker_conf_m8` repository containing the necessary files. **Remember to replace `"YOUR_DOCKER_HOST_IP_HERE"` with the actual IP you intend to use for your Docker dummy interface (e.g., `10.254.254.1`)**. This IP will be embedded in the certificates.

The repository contains:

* **`scripts/validate_docker_host_ip.sh`**:
  * **Purpose**: This script ensures that the `DOCKER_HOST_IP` environment variable is set and contains a valid IPv4 address. It's a crucial prerequisite for generating correct certificates.
  * **Location**: [https://github.com/mano8/docker_conf_m8/blob/main/scripts/validate_docker_host_ip.sh](https://github.com/mano8/docker_conf_m8/blob/main/scripts/validate_docker_host_ip.sh)

* **`ssl_conf/ssl_docker_server.conf`**:
  * **Purpose**: This is a template for the Docker daemon's server certificate. It defines default OpenSSL settings, organizational details, and placeholder `alt_names` (Subject Alternative Names). The `IP.2` entry will be dynamically updated by the certificate generation script to ensure it matches your `DOCKER_HOST_IP`.
  * **Location**: [https://github.com/mano8/docker_conf_m8/blob/main/ssl_conf/ssl_docker_server.conf](https://github.com/mano8/docker_conf_m8/blob/main/ssl_conf/ssl_docker_server.conf)

* **`ssl_conf/ssl_docker_client.conf`**:
  * **Purpose**: This is a template for the client certificate used by applications like Traefik. Similar to the server config, it defines details and placeholder `alt_names` that will be dynamically updated.
  * **Location**: [https://github.com/mano8/docker_conf_m8/blob/main/ssl_conf/ssl_docker_client.conf](https://github.com/mano8/docker_conf_m8/blob/main/ssl_conf/ssl_docker_client.conf)

* **`scripts/manage_docker_certs.sh`**:
  * **Purpose**: This is the core script that automates the entire certificate management process. It generates the Certificate Authority (CA) key and certificate, the Docker daemon's server key and certificate, and the client key and certificate (for Traefik). It also handles permissions and ownership, including setting correct ownership for client certificates for `userns-remap` environments. It can also remove all generated certificates.
  * **Location**: [https://github.com/mano8/docker_conf_m8/blob/main/scripts/manage_docker_certs.sh](https://github.com/mano8/docker_conf_m8/blob/main/scripts/manage_docker_certs.sh)

#### 2.2.2. Generate Certificates

Execute the `manage_docker_certs.sh` script to generate all necessary mTLS certificates and keys. This script uses the templates and validates the `DOCKER_HOST_IP` you set earlier.

```bash
sudo "${BASE_DIR}/scripts/manage_docker_certs.sh" generate
```

*Explanation*: This command runs the certificate management script in `generate` mode. It will create:

* **Server Certificates**: `ca.pem`, `server-key.pem`, `server-cert.pem` in `/etc/docker/certs/` (for the Docker daemon).
* **Client Certificates**: `ca.pem`, `client-key.pem`, `client-cert.pem` in `/opt/docker_conf_m8/certs/` (for client applications like Traefik).
The client certificates directory will be chowned to the `dockremap` UID to ensure proper permissions when mounted into remapped containers.

---

## 3. Configure Dummy Interface

We'll create a dedicated dummy network interface, `docker0`, to host the Docker API endpoint securely.

### 3.1. Create `docker0` Interface

Create a `systemd-networkd` configuration file for the dummy interface.

```bash
sudo nano /etc/systemd/network/50-docker0-dummy.netdev
```

Paste the following content:

```ini
[NetDev]
Name=docker0
Kind=dummy
```

*Explanation*: This file defines a network device named `docker0` of type `dummy`. Dummy interfaces are virtual interfaces that don't correspond to physical hardware, making them ideal for isolated local communication.

### 3.2. Configure `docker0` IP Address

Create a `systemd-networkd` configuration file for the IP address of the dummy interface. This IP must match the `DOCKER_HOST_IP` you set when generating certificates.

```bash
sudo nano /etc/systemd/network/51-docker0-dummy.network
```

Paste the following content:

```ini
[Match]
Name=docker0

[Network]
Address=10.254.254.1/24
```

*Explanation*: This file configures the `docker0` interface, assigning it the static IP address `10.254.254.1` with a /24 subnet mask. **Ensure this IP address matches the `DOCKER_HOST_IP` you defined earlier.**

### 3.3. Apply Network Configuration

Enable and restart `systemd-networkd` to bring up the dummy interface.

```bash
sudo systemctl enable systemd-networkd
sudo systemctl restart systemd-networkd
```

*Explanation*: These commands ensure `systemd-networkd` starts automatically on boot and then restarts it to apply the new network configurations.

### 3.4. Verify `docker0` Status

Check if the `docker0` interface is up and has the correct IP.

```bash
ip addr show docker0
```

*Example Output*:

```
4: docker0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether 02:c2:d9:2d:c2:5f brd ff:ff:ff:ff:ff:ff
    inet 10.254.254.1/24 scope global docker0
       valid_lft forever preferred_lft forever
```

*Explanation*: This command displays the details of the `docker0` interface, confirming its status and assigned IP address.

---

## 4. Configure Docker Daemon for mTLS

Now, instruct the Docker daemon to listen on the secure dummy interface using mTLS.

### 4.1. Modify `/etc/docker/daemon.json`

Open the Docker daemon configuration file again.

```bash
sudo nano /etc/docker/daemon.json
```

Modify its content to include the `hosts` and `tls*` settings. The `userns-remap`, `experimental`, and `storage-driver` settings should remain.

```json
{
  "userns-remap": "default",
  "experimental": false,
  "storage-driver": "overlay2",
  "hosts": ["unix:///var/run/docker.sock", "tcp://10.254.254.1:2376"],
  "tlsverify": true,
  "tlscacert": "/etc/docker/certs/ca.pem",
  "tlscert": "/etc/docker/certs/server-cert.pem",
  "tlskey": "/etc/docker/certs/server-key.pem"
}
```

*Explanation*:

* `"hosts": ["unix:///var/run/docker.sock", "tcp://10.254.254.1:2376"]`: This tells Docker to listen on both the local Unix socket (for local CLI access) and the secure TCP port 2376 on the `docker0` interface (for remote/container access).
* `"tlsverify": true`: Enforces mutual TLS, meaning both the client and server must present valid certificates.
* `"tlscacert"`, `"tlscert"`, `"tlskey"`: Specify the paths to the CA certificate, the Docker daemon's server certificate, and its private key, respectively. These were generated in the previous steps.

### 4.2. Restart Docker Daemon

Restart Docker to apply the new API and TLS configurations.

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

*Explanation*: Similar to before, this reloads `systemd` configurations and restarts Docker to pick up the changes in `daemon.json`.

---

## 5. Verify Remote TLS Connection

Test the mTLS connection from your host using the client certificates.

### 5.1. Set Docker Environment Variables

Define environment variables that point to your client certificates and the secure Docker API endpoint.

```bash
export DOCKER_TLS_VERIFY="1"
export DOCKER_CERT_PATH="/opt/docker_conf_m8/certs"
export DOCKER_HOST="tcp://10.254.254.1:2376"
```

*Explanation*:

* `DOCKER_TLS_VERIFY="1"`: Tells the Docker CLI to verify the server's certificate against the CA and ensure mutual authentication.
* `DOCKER_CERT_PATH`: Points to the directory containing your client's `ca.pem`, `client-cert.pem`, and `client-key.pem`.
* `DOCKER_HOST`: Specifies the IP address and port of the Docker daemon's secure TLS endpoint.

### 5.2. Test Connection

Now, try a Docker command using these secure settings.

```bash
docker ps
```

*Expected Output*: You should see an empty list of running containers or any containers you might have started, without any TLS handshake errors.
*Explanation*: If this command runs successfully, it confirms that your Docker CLI can securely communicate with the Docker daemon over the mTLS-secured TCP endpoint.

---

## 6. Configure UFW (Uncomplicated Firewall)

Secure your host by ensuring only necessary traffic can reach the Docker API.

**IMPORTANT SECURITY NOTE:** When enabling UFW, ensure you allow SSH traffic first, otherwise you might lose connectivity to your server!

### 6.1. Allow SSH (Critical)

Allow your SSH port (default is 22) before enabling UFW.

```bash
sudo ufw allow ssh comment 'Allow SSH access'
# If SSH runs on a non-standard port, e.g., 2222:
# sudo ufw allow 2222/tcp comment 'Allow SSH on custom port'
```

*Explanation*: This rule explicitly permits incoming SSH connections, preventing you from being locked out when the firewall is activated.

### 6.2. Configure Default Policies and Enable Firewall

Set the default UFW policies and enable the firewall.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

*Explanation*: These commands set the default policy to deny all incoming connections and allow all outgoing connections. `sudo ufw enable` activates the firewall. You will be prompted to confirm; type `y` and press Enter.

### 6.3. Allow Docker API Access from Traefik (Docker Bridge Network)

The `docker0` dummy interface is for internal host communication. Your Traefik container, running on a Docker bridge network (`traefik_proxy`), will communicate with the Docker daemon via Docker's internal networking. UFW needs a rule to allow this specific internal traffic.

First, identify the subnet of your `traefik_proxy` network:

```bash
docker network inspect traefik_proxy | grep -A 3 'IPAM' | grep 'Subnet'
```

*Example Output*: `"Subnet": "172.18.0.0/16",`
*Explanation*: This command inspects your `traefik_proxy` network and extracts its IP subnet. You will use this subnet in the UFW rule.

Now, add the UFW rule:

```bash
# REPLACE <TRAEFIK_NETWORK_SUBNET> with the actual subnet from the command above (e.g., 172.18.0.0/16)
sudo ufw allow in on docker0 from <TRAEFIK_NETWORK_SUBNET> to 10.254.254.1 port 2376 proto tcp comment 'Allow Traefik container to access Docker API'
```

*Explanation*: This rule explicitly allows incoming TCP traffic on the `docker0` dummy interface, originating from *any IP within your `traefik_proxy` Docker network's subnet*, destined for the `10.254.254.1` IP on port 2376. This ensures Traefik can connect while external access remains blocked by the default deny policy.

### 6.4. Verify UFW Status

Check the active UFW rules.

```bash
sudo ufw status verbose
```

*Explanation*: This command displays all active UFW rules and their status, confirming your configurations are applied.

---

## 7. Configure Traefik with mTLS

Finally, configure Traefik to connect to the Docker daemon using the mTLS client certificates over the dummy interface.

### 7.1. Create `docker-compose.yml`

Create a `docker-compose.yml` file for your Traefik service.

```bash
nano docker-compose.yml
```

Paste the following content:

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v3.4.0 # Updated to the latest stable version
    container_name: traefik
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    networks:
      - traefik_proxy
    ports:
      - "80:80"   # The HTTP port
      - "443:443" # The HTTPS port
      # - "8080:8080" # The Dashboard (optional)
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro # Used only for Docker provider to listen for events, NOT for API access
      - /etc/traefik:/etc/traefik:ro # Configuration directory
      - /opt/docker_conf_m8/certs:/etc/traefik/certs:ro # Mount client certificates from the host
    environment:
      # Docker Host configuration for mTLS
      - DOCKER_HOST=tcp://10.254.254.1:2376
      - DOCKER_TLS_VERIFY=1
      - DOCKER_CERT_PATH=/etc/traefik/certs # Path to client certs INSIDE the container
      # Basic Traefik configuration
      - TZ=Europe/Madrid # Set your timezone
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=Host(`traefik.example.com`)" # Change to your domain
      - "traefik.http.routers.api.entrypoints=websecure"
      - "traefik.http.routers.api.service=api@internal"
      - "traefik.http.routers.api.middlewares=auth"
      - "traefik.http.middlewares.auth.basicauth.users=youruser:$$apr1$$YOURHASHEDPASSWORDHERE" # Generate with 'echo $(htpasswd -nb youruser yourpassword)'
      - "traefik.http.routers.api.tls.certresolver=myresolver" # If using HTTPS
      # Global Redirect HTTP to HTTPS (optional)
      - "traefik.http.middlewares.redirect-https.redirectscheme.scheme=https"
      - "traefik.http.routers.web-http.rule=HostRegexp(`{host:.+}`)"
      - "traefik.http.routers.web-http.entrypoints=web"
      - "traefik.http.routers.web-http.middlewares=redirect-https"

networks:
  traefik_proxy:
    external: true # Assumes you have a bridge network named traefik_proxy
```

*Explanation*:

* **`image: traefik:v3.4.0`**: Specifies the Traefik image version, now updated.
* **`security_opt: - no-new-privileges:true`**: Enhances container security by preventing privilege escalation.
* **`volumes`**:
  * `/var/run/docker.sock:/var/run/docker.sock:ro`: **Crucial point**: Traefik's Docker provider needs access to `docker.sock` to *listen for Docker events* (container starts/stops, label changes). However, it will **not** use this socket for API communication when `DOCKER_HOST` is set to a TCP endpoint. This is a common pattern for Traefik and ensures it can dynamically configure itself based on your Docker setup. The `:ro` makes it read-only.
  * `/opt/docker_conf_m8/certs:/etc/traefik/certs:ro`: This mounts the client certificates generated earlier from your host into the Traefik container. The certificates will be available inside the container at `/etc/traefik/certs`.
* **`environment`**:
  * `DOCKER_HOST=tcp://10.254.254.1:2376`: Instructs Traefik to connect to the Docker daemon via the secure TCP endpoint on your dummy interface.
  * `DOCKER_TLS_VERIFY=1`: Tells Traefik's Docker client to verify the Docker daemon's certificate.
  * `DOCKER_CERT_PATH=/etc/traefik/certs`: Specifies the path *inside the container* where the client certificates are mounted.
* **`labels`**: Standard Traefik labels for routing and services. Remember to adjust `Host(`traefik.example.com`)` to your actual domain.
* **`networks`**: Connects Traefik to an external network, typically used for other containers Traefik manages. Create this network if it doesn't exist: `docker network create traefik_proxy`.

### 7.2. Create Traefik Configuration (`/etc/traefik/traefik.yml`)

Create a basic Traefik configuration file to enable the Docker provider and define entrypoints.

```bash
sudo nano /etc/traefik/traefik.yml
```

Paste the following content (adjust as needed for your specific Traefik setup):

```yaml
api:
  dashboard: true
  insecure: false # Set to true if you expose dashboard on 8080 without auth/TLS

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: "websecure"
          scheme: "https"
  websecure:
    address: ":443"

providers:
  docker:
    endpoint: "tcp://10.254.254.1:2376" # Point to the secure Docker API
    tls:
      ca: "/etc/traefik/certs/ca.pem"
      cert: "/etc/traefik/certs/client-cert.pem"
      key: "/etc/traefik/certs/client-key.pem"
      insecureSkipVerify: false
    exposedByDefault: false # Only expose containers with traefik.enable=true label

certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com # Change to your email
      storage: "/etc/traefik/acme.json" # Ensure this path is mounted as a volume
      httpChallenge:
        entryPoint: web
```

*Explanation*:

* **`api.dashboard`**: Enables the Traefik dashboard.
* **`entryPoints`**: Defines HTTP (`web`) and HTTPS (`websecure`) entry points.
* **`providers.docker`**:
  * `endpoint: "tcp://10.254.254.1:2376"`: This is the critical part, instructing Traefik to connect to the Docker API at the mTLS-secured dummy interface IP and port.
  * `tls`: Configures Traefik's TLS client.
    * `ca`: Path to the CA certificate **inside the container**.
    * `cert`: Path to the client's public certificate **inside the container**.
    * `key`: Path to the client's private key **inside the container**.
    * `insecureSkipVerify: false`: Ensures Traefik verifies the Docker daemon's certificate.
  * `exposedByDefault: false`: Best practice to only route traffic to containers explicitly enabled with Traefik labels.
* **`certificatesResolvers.myresolver`**: Configures ACME (Let's Encrypt) for automatic SSL certificate management. Remember to set your correct email address.

### 7.3. Start Traefik

Finally, start your Traefik service using Docker Compose.

```bash
docker compose up -d
```

*Explanation*: This command starts the Traefik container in detached mode, applying all the configurations. Traefik should now be securely connected to your Docker daemon via mTLS over the dummy interface.

---

This complete setup provides a highly secure and isolated Docker environment, especially beneficial for configurations involving self-hosting applications with tools like Traefik.

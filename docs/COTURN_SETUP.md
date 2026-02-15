# coturn Setup for CatRealm Voice Chat

This guide explains how to set up coturn (STUN/TURN server) for WebRTC voice chat in CatRealm.

## What is coturn?

coturn is an open-source STUN and TURN server that enables WebRTC connections to work behind NAT/firewalls.

- **STUN**: Helps discover public IP addresses
- **TURN**: Relays voice traffic when direct peer-to-peer fails

## Installation

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y coturn
```

### Enable coturn Service

```bash
# Uncomment TURNSERVER_ENABLED=1 in /etc/default/coturn
sudo sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
```

## Configuration

### 1. Generate Credentials

```bash
# Generate a random secret for TURN authentication
TURN_SECRET=$(openssl rand -hex 32)
echo "Your TURN secret: $TURN_SECRET"
```

Save this secret - you'll need it for both coturn config and the self-hostable server.

### 2. Configure coturn

Edit `/etc/turnserver.conf`:

```bash
sudo nano /etc/turnserver.conf
```

**Recommended configuration**:

```conf
# Listening port for TURN (default 3478)
listening-port=3478

# External IP (replace with your server's public IP)
# Find it with: curl -4 ifconfig.me
external-ip=YOUR_PUBLIC_IP

# Relay ports for media
min-port=49152
max-port=65535

# Enable fingerprinting
fingerprint

# Use long-term credentials
lt-cred-mech
use-auth-secret
static-auth-secret=YOUR_TURN_SECRET_HERE

# Realm (your domain or server name)
realm=catrealm

# Verbose logging (disable in production)
verbose

# Log file
log-file=/var/log/turnserver.log

# Deny loopback addresses
no-loopback-peers

# Deny private IP ranges from being relayed
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.0.2.0-192.0.2.255
denied-peer-ip=192.88.99.0-192.88.99.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=198.51.100.0-198.51.100.255
denied-peer-ip=203.0.113.0-203.0.113.255
denied-peer-ip=240.0.0.0-255.255.255.255

# TLS (optional but recommended)
# Uncomment and configure if you have SSL certificates
# cert=/path/to/cert.pem
# pkey=/path/to/privkey.pem
```

**Important**: Replace:
- `YOUR_PUBLIC_IP` - Your server's public IP (get with `curl -4 ifconfig.me`)
- `YOUR_TURN_SECRET_HERE` - The secret you generated above

### 3. Firewall Configuration

Open required ports:

```bash
# TURN server port
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp

# Media relay ports
sudo ufw allow 49152:65535/udp
```

### 4. Start coturn

```bash
sudo systemctl enable coturn
sudo systemctl start coturn
sudo systemctl status coturn
```

### 5. Verify coturn is Running

```bash
# Check if coturn is listening
sudo netstat -tulpn | grep 3478

# Check logs
sudo tail -f /var/log/turnserver.log
```

## Configure CatRealm Server

Add the TURN secret to your self-hostable server's `.env`:

```bash
# In /path/to/CatRealm-SelfHostableServer/.env
TURN_SECRET=your_turn_secret_here
TURN_PORT=3478
```

The server will automatically expose TURN credentials via `/api/turn/credentials`.

## Testing

### Test STUN

```bash
# Install stun client
sudo apt-get install stuntman-client

# Test STUN
stunclient YOUR_PUBLIC_IP 3478
```

Expected output: Your public IP and port mapping

### Test TURN

Use Trickle ICE tool: https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/

Add your TURN server:
- **URI**: `turn:YOUR_PUBLIC_IP:3478`
- **Username**: `test`
- **Password**: Generate with:
  ```bash
  # TURN username is timestamp-based: timestamp:username
  # Password is HMAC-SHA1 of username with secret
  echo -n "$(date +%s):test" | openssl dgst -sha1 -hmac "YOUR_TURN_SECRET" -binary | base64
  ```

Click "Gather candidates" - you should see `relay` candidates appear.

## Troubleshooting

### coturn won't start

```bash
# Check logs
sudo journalctl -u coturn -n 50

# Common issues:
# - Port 3478 already in use (check with: sudo lsof -i :3478)
# - Invalid config syntax
# - Missing external-ip
```

### No relay candidates

1. Check firewall allows UDP ports 49152-65535
2. Verify external-ip matches your public IP
3. Check credentials are correct
4. Enable verbose logging in turnserver.conf

### High bandwidth usage

TURN relays ALL voice traffic for clients behind strict NAT. To reduce:
- Ensure STUN works (most clients should use direct peer-to-peer)
- Monitor with: `sudo iftop -i eth0`
- Set bandwidth limits in turnserver.conf if needed

## Production Recommendations

1. **Use TLS** - Configure SSL certificates for encrypted TURN (port 5349)
2. **Monitor bandwidth** - TURN can use significant traffic
3. **Rotate secrets** - Change TURN_SECRET periodically
4. **Disable verbose logging** - Remove `verbose` from config
5. **Set rate limits** - Use `user-quota` and `total-quota` in config
6. **Backup config** - Keep turnserver.conf in version control

## Resource Usage

**Typical usage**:
- **CPU**: Low (5-10% per 10 concurrent voice users)
- **RAM**: ~50MB base + ~5MB per active relay
- **Bandwidth**: Variable
  - STUN: Negligible (~1KB per request)
  - TURN relay: ~50-100 KB/s per voice stream

**Plan for**:
- 10 users in voice = ~500KB/s outbound (~1.7GB/hour)
- Most users will use direct peer-to-peer (STUN only)
- Only ~20-30% typically need TURN relay

## Security Notes

- ✅ TURN secret is never exposed to clients (server generates temporary credentials)
- ✅ Private IP ranges are blocked from relay
- ✅ Credentials expire (time-limited)
- ✅ Optional: Enable TLS for encrypted signaling
- ⚠️ TURN can be used to relay any UDP traffic - use rate limits

## References

- coturn GitHub: https://github.com/coturn/coturn
- WebRTC TURN spec: https://datatracker.ietf.org/doc/html/rfc5766
- Testing tools: https://webrtc.github.io/samples/

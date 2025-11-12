# AppArmor Confinement for Honeypot IDS

## Overview

AppArmor is a Linux Security Module (LSM) that provides Mandatory Access Control (MAC) for applications. This directory contains AppArmor profiles to confine the Flask honeypot and Scapy IDS components.

## Why AppArmor?

AppArmor limits what system resources and files an application can access, even if the application is compromised. This follows the **principle of least privilege**.

Benefits:
- Restricts file system access to only necessary paths
- Limits network capabilities
- Prevents unauthorized system modifications
- Provides defense-in-depth security layer
- Logs policy violations for security auditing

## Profiles Included

### 1. usr.bin.honeypot-flask

Confines the Flask honeypot application with:
- Read access to application code and config
- Write access to `/var/log/honeypot_web/` only
- Network access for listening on port 8080
- Read-only access to GeoIP database
- Denies access to sensitive system files (`/etc/shadow`, SSH keys, etc.)

### 2. usr.bin.scapy-ids

Confines the Scapy IDS with:
- Read access to application code and config
- Write access to `/var/log/honeypot_web/` only
- Raw socket access for packet capture (requires CAP_NET_RAW)
- Network admin capabilities for iptables blocking
- Execute access to blocking scripts
- Read access to network interface information
- Denies access to sensitive system files

## Installation Steps

### 1. Copy Profiles

```bash
sudo cp apparmor/profiles/* /etc/apparmor.d/
```

### 2. Adjust Paths (if needed)

Edit the profiles to match your installation path:

```bash
sudo nano /etc/apparmor.d/usr.bin.honeypot-flask
sudo nano /etc/apparmor.d/usr.bin.scapy-ids
```

Change `/opt/ids-honeypot-apparmor-elk/` to your actual installation directory.

### 3. Load Profiles in Complain Mode

Start with **complain mode** for testing. This logs policy violations without blocking:

```bash
# Flask honeypot
sudo aa-complain /etc/apparmor.d/usr.bin.honeypot-flask
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask

# Scapy IDS
sudo aa-complain /etc/apparmor.d/usr.bin.scapy-ids
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.scapy-ids
```

Verify profiles are loaded:
```bash
sudo aa-status
```

### 4. Test the Applications

Run the honeypot and IDS as normal:

```bash
# Terminal 1: Flask honeypot
python3 app/file.py

# Terminal 2: Scapy IDS
sudo python3 ids/scapy_ids.py
```

Test functionality:
```bash
# Test honeypot
curl http://localhost:8080/

# Run attack simulator
python3 scripts/attacker_simulator.py --target localhost
```

### 5. Monitor AppArmor Logs

Check for denials and violations:

```bash
# Monitor in real-time
sudo tail -f /var/log/syslog | grep apparmor

# Or use audit logs
sudo tail -f /var/log/audit/audit.log | grep AVC

# Check specific denials
sudo grep DENIED /var/log/syslog | grep honeypot
```

### 6. Refine Profiles (if needed)

If legitimate operations are blocked:

1. Identify the denied operation in logs
2. Edit the profile to allow the specific access
3. Reload the profile:
   ```bash
   sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask
   ```
4. Test again

### 7. Enforce Profiles

Once testing is complete and no legitimate operations are blocked:

```bash
# Switch to enforce mode
sudo aa-enforce /etc/apparmor.d/usr.bin.honeypot-flask
sudo aa-enforce /etc/apparmor.d/usr.bin.scapy-ids

# Verify
sudo aa-status
```

## Profile Modes

AppArmor has three modes:

1. **Complain Mode**: Logs violations but allows operations (for testing)
2. **Enforce Mode**: Actively blocks violations (for production)
3. **Disabled**: Profile not active

Switch between modes:

```bash
# Complain mode
sudo aa-complain /etc/apparmor.d/usr.bin.honeypot-flask

# Enforce mode
sudo aa-enforce /etc/apparmor.d/usr.bin.honeypot-flask

# Disable
sudo ln -s /etc/apparmor.d/usr.bin.honeypot-flask /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.honeypot-flask
```

## Common Operations

### Check Profile Status

```bash
sudo aa-status | grep honeypot
sudo aa-status | grep scapy
```

### Reload After Changes

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.honeypot-flask
```

### Unload Profile

```bash
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.honeypot-flask
```

### View Denials

```bash
# Recent denials
sudo journalctl -xe | grep apparmor | grep DENIED

# Specific timeframe
sudo journalctl --since "1 hour ago" | grep apparmor
```

## Troubleshooting

### Application Won't Start

**Symptom**: Application fails to start or crashes immediately

**Solution**:
1. Check AppArmor logs: `sudo grep DENIED /var/log/syslog`
2. Switch to complain mode for debugging
3. Identify missing permissions
4. Update profile accordingly

### Network Operations Blocked

**Symptom**: Cannot connect to Logstash or external services

**Solution**:
- Ensure `network inet stream,` is present in profile
- Check for specific port restrictions
- Verify DNS resolution is allowed (`/etc/resolv.conf r`)

### File Access Denied

**Symptom**: Cannot read/write files

**Solution**:
1. Verify paths in profile match actual installation
2. Check file permissions independently: `ls -la /path/to/file`
3. Add specific path to profile if legitimate access

### Scapy Cannot Capture Packets

**Symptom**: IDS fails to sniff network traffic

**Solution**:
- Verify `capability net_raw,` is in profile
- Check raw socket permissions: `network packet raw,`
- May need to run with `sudo` even with AppArmor
- Grant capabilities: `sudo setcap cap_net_raw=eip /usr/bin/python3`

### Profile Won't Load

**Symptom**: `apparmor_parser` errors

**Solution**:
1. Check syntax: `sudo apparmor_parser -Q /etc/apparmor.d/usr.bin.honeypot-flask`
2. Verify abstractions exist: `ls /etc/apparmor.d/abstractions/`
3. Check file permissions on profile

## Security Considerations

### What AppArmor Protects Against

- **File system traversal**: Limits access to specified directories
- **Privilege escalation**: Restricts capability usage
- **Data exfiltration**: Controls network access patterns
- **Unauthorized system changes**: Prevents writing to sensitive locations

### What AppArmor Does NOT Protect Against

- **Application logic bugs**: SQL injection in Flask code still works
- **Network attacks**: AppArmor doesn't inspect packet contents
- **Memory corruption**: Use additional tools like ASLR, stack canaries
- **Social engineering**: User-level attacks bypass MAC

### Defense in Depth

AppArmor is ONE layer in a comprehensive security strategy:

1. **Firewall**: iptables/nftables for network filtering
2. **AppArmor**: MAC for application confinement
3. **SELinux** (alternative): More complex MAC system
4. **Secure coding**: Validate inputs, sanitize outputs
5. **Regular updates**: Keep system and dependencies patched
6. **Monitoring**: IDS/IPS for threat detection
7. **Backups**: Regular backups of critical data

## Container Considerations

**Important**: AppArmor profiles may not work inside containers (Docker, LXC) depending on configuration.

If running in Docker:
- Container must be run with `--security-opt apparmor=profile_name`
- Host must have AppArmor enabled
- Profile must be loaded on the host

If AppArmor is unavailable in your environment:
- Use alternative confinement (SELinux, seccomp)
- Rely on container isolation
- Implement strong input validation in code
- Run with minimal user privileges

## Production Recommendations

1. **Start with complain mode** for 24-48 hours in production
2. **Review all denials** to ensure no false positives
3. **Switch to enforce mode** gradually
4. **Monitor continuously** for unexpected denials
5. **Document customizations** made to profiles
6. **Version control profiles** along with application code
7. **Test profile changes** in staging before production

## Additional Resources

- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [Ubuntu AppArmor Guide](https://ubuntu.com/server/docs/security-apparmor)
- [Profile Syntax Reference](https://gitlab.com/apparmor/apparmor/-/wikis/QuickProfileLanguage)
- [AppArmor Tools](https://gitlab.com/apparmor/apparmor/-/wikis/Profiling_with_tools)

## Support

For issues specific to this project:
- Check logs: `/var/log/syslog` and `/var/log/honeypot_web/`
- Review profile syntax carefully
- Consult AppArmor documentation
- Test in complain mode first

---

**Last Updated**: 2025-11-11

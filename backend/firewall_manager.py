import ipaddress
import subprocess


def is_blockable(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return False

    if ip.version != 4:
        return False

    if ip.is_private:
        return False

    if ip.is_loopback:
        return False

    if ip.is_multicast:
        return False

    if ip.is_link_local:
        return False

    if ip.is_reserved:
        return False

    if ip.is_unspecified:
        return False

    return True


def choose_remote_ip(src_ip, dst_ip):

    src_ok = is_blockable(src_ip)
    dst_ok = is_blockable(dst_ip)

    if src_ok and not dst_ok:
        return src_ip

    if dst_ok and not src_ok:
        return dst_ip

    return None


def block_ip(ip_address):

    if not is_blockable(ip_address):
        return {
            "success": False,
            "message": "This IP is protected and cannot be blocked."
        }

    safe_name = ip_address.replace(".", "-")

    inbound_rule = f"SENTINALS-BLOCK-{safe_name}-IN"
    outbound_rule = f"SENTINALS-BLOCK-{safe_name}-OUT"

    command = f'''
    if (-not (Get-NetFirewallRule -DisplayName "{inbound_rule}" -ErrorAction SilentlyContinue)) {{
        New-NetFirewallRule `
        -DisplayName "{inbound_rule}" `
        -Direction Inbound `
        -RemoteAddress "{ip_address}" `
        -Action Block `
        -Profile Any
    }}

    if (-not (Get-NetFirewallRule -DisplayName "{outbound_rule}" -ErrorAction SilentlyContinue)) {{
        New-NetFirewallRule `
        -DisplayName "{outbound_rule}" `
        -Direction Outbound `
        -RemoteAddress "{ip_address}" `
        -Action Block `
        -Profile Any
    }}
    '''

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return {
            "success": False,
            "message": result.stderr.strip()
            or "Windows Firewall block failed."
        }

    return {
        "success": True,
        "ip_address": ip_address,
        "message": f"{ip_address} successfully blocked."
    }

def unblock_ip(ip_address):

    safe_name = ip_address.replace(".", "-")

    inbound_rule = f"SENTINALS-BLOCK-{safe_name}-IN"
    outbound_rule = f"SENTINALS-BLOCK-{safe_name}-OUT"

    command = f'''
    Get-NetFirewallRule `
      -DisplayName "{inbound_rule}" `
      -ErrorAction SilentlyContinue |
      Remove-NetFirewallRule

    Get-NetFirewallRule `
      -DisplayName "{outbound_rule}" `
      -ErrorAction SilentlyContinue |
      Remove-NetFirewallRule
    '''

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        print("UNBLOCK ERROR:", result.stderr)

        return {
            "success": False,
            "message":
                result.stderr.strip()
                or "Unable to unblock IP."
        }

    return {
        "success": True,
        "ip_address": ip_address,
        "message":
            f"{ip_address} successfully unblocked."
    }
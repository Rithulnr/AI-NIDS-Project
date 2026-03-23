import subprocess

blocked_ips = set()

def block_ip(ip):

    rule_name = f"IDS_Block_{ip}"

    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'

    subprocess.run(cmd, shell=True)

    blocked_ips.add(ip)


def neutralize(ip, risk):

    if risk > 0.85:

        if ip not in blocked_ips:
            block_ip(ip)

        return "BLOCKED"

    elif risk > 0.65:
        return "RATE_LIMIT"

    elif risk > 0.45:
        return "MONITOR"

    else:
        return "ALLOW"
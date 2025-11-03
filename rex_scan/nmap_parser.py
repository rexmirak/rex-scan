"""Parse nmap XML output into a normalized Python structure."""
import xml.etree.ElementTree as ET
from typing import Dict, Any


def parse_nmap_xml(path: str) -> Dict[str, Any]:
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"nmap": "http://www.nmap.org/xsd/1.0"}

    result = {"hosts": []}
    for host in root.findall("host"):
        h = {"addresses": [], "hostnames": [], "ports": []}
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            addr_val = addr.get("addr")
            h["addresses"].append({"type": addr_type, "addr": addr_val})
        hn = host.find("hostnames")
        if hn is not None:
            for name in hn.findall("hostname"):
                h["hostnames"].append(name.get("name"))

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                p = {}
                p["portid"] = port.get("portid")
                p["protocol"] = port.get("protocol")
                state = port.find("state")
                p["state"] = state.get("state") if state is not None else "unknown"
                svc = port.find("service")
                if svc is not None:
                    p["service"] = {
                        "name": svc.get("name"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "extrainfo": svc.get("extrainfo"),
                    }
                else:
                    p["service"] = None
                # collect script outputs if any
                scripts = []
                for script in port.findall("script"):
                    scripts.append({"id": script.get("id"), "output": script.get("output")})
                if scripts:
                    p["scripts"] = scripts
                h["ports"].append(p)

        result["hosts"].append(h)

    return result

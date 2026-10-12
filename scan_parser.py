"""Lossless extraction of existing Nmap XML; never executes a scan."""
import xml.etree.ElementTree as ET


def parse_services(host):
    ports = []
    for element in host.findall("ports/port"):
        state = element.find("state")
        service = element.find("service")
        port = {
            "protocol": element.get("protocol"), "port": int(element.get("portid")),
            "state": state.get("state") if state is not None else "unknown",
            "state_metadata": dict(state.attrib) if state is not None else {},
            "service": None, "product": None, "version": None,
            "service_metadata": dict(service.attrib) if service is not None else {},
            "cpe": [c.text.strip() for c in service.findall("cpe") if c.text]
                   if service is not None else [],
            "scripts": [{"id": s.get("id"), "output": s.get("output"),
                         "xml": ET.tostring(s, encoding="unicode")}
                        for s in element.findall("script")],
        }
        if service is not None:
            for key in ("product", "version", "extrainfo", "ostype", "devicetype",
                        "tunnel", "method", "conf"):
                port[key] = service.get(key)
            port["service"] = service.get("name")
        ports.append(port)
    return ports


def scan_metadata(root, host):
    finished = root.find("runstats/finished")
    status = host.find("status")
    infos = [dict(info.attrib) for info in root.findall("scaninfo")]
    return {
        "complete": bool(finished is not None and finished.get("exit") == "success"
                         and status is not None and status.get("state") == "up"
                         and host.get("timedout") != "true" and infos),
        "scaninfo": infos,
        "host_status": dict(status.attrib) if status is not None else {},
        "finished": dict(finished.attrib) if finished is not None else {},
        "timedout": host.get("timedout") == "true",
    }


def covered_port(metadata, protocol, port):
    if not metadata.get("complete"):
        return False
    for info in metadata.get("scaninfo", []):
        if info.get("protocol") != protocol:
            continue
        for entry in info.get("services", "").split(","):
            try:
                limits = [int(v) for v in entry.split("-")]
                if len(limits) == 1 and limits[0] == port:
                    return True
                if len(limits) == 2 and limits[0] <= port <= limits[1]:
                    return True
            except ValueError:
                continue
    return False

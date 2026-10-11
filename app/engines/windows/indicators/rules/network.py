"""Network rules. A connection is context, never a finding by itself."""
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, is_public_ip
from app.engines.windows.indicators.helpers import full_name, is_high_risk_dir, is_interpreter, looks_temp

_LIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RCVD", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT"}


def external_connections(process):
    out = []
    for c in process.network:
        if c.remote_address and is_public_ip(c.remote_address) and (not c.state or c.state.upper() in _LIVE_STATES):
            out.append(c)
    return out


class NetworkWithOtherSuspicionRule(IndicatorRule):
    rule_id = "NET-001"
    category = "network"
    name = "External network activity from an already suspicious process"
    description = "A public-IP connection is only reported when the process also runs from a risky folder, is an interpreter, or has executable private memory with an MZ/shellcode start."

    def evaluate(self, result):
        from app.engines.windows.indicators.rules.memory import classify_region
        findings = []
        for p in result.processes:
            conns = external_connections(p)
            if not conns:
                continue
            reasons = []
            if p.path and is_high_risk_dir(p.path):
                reasons.append("executable runs from a temporary/user-writable folder")
            if is_interpreter(full_name(p)):
                reasons.append("process is a command or scripting interpreter")
            modules = {d.name.lower() for d in p.dlls}
            if any(classify_region(r, modules)[0] == "High" for r in p.memory_regions):
                reasons.append("process has injected-code evidence in memory")
            if not reasons:
                continue
            findings.append(self.make(
                title="External connection from a process with other suspicious traits", severity="Medium", confidence="Medium", process=p,
                summary="The network activity is context for another suspicious characteristic of the same process.",
                reasons=reasons, evidence=[f"{c.local} → {c.remote} ({c.state or 'state unknown'})" for c in conns[:15]],
                source_plugins=["windows.netscan", "windows.netstat"]))
        return findings


class UnexpectedNetworkProcessRule(IndicatorRule):
    rule_id = "NET-002"
    category = "network"
    name = "Network connection from a process that normally has none"
    description = "smss/csrss/wininit/winlogon/notepad/calc/... holding a live connection to a public address."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            if full_name(p) not in baseline.NO_NETWORK_EXPECTED:
                continue
            conns = external_connections(p)
            if not conns:
                continue
            findings.append(self.make(
                title=f"{p.name} has an external network connection", severity="Medium", confidence="Medium", process=p,
                summary=f"{p.name} does not normally communicate over the network.",
                reasons=[f"{len(conns)} external connection(s)"], evidence=[f"{c.local} → {c.remote} ({c.state or 'state unknown'})" for c in conns[:15]],
                source_plugins=["windows.netscan", "windows.netstat"]))
        return findings

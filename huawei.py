import datetime
import itertools
from aerleon.lib import aclgenerator # type: ignore
from aerleon.lib import nacaddr # type: ignore
from aerleon.lib import plugin # type: ignore
from aerleon.lib import policy # type: ignore


class Error(Exception):
    """Generic error class."""


class FilterNameLengthError(Error):
    """Raised when filter name is too long."""


ANY_PORT = (0, 65535)
ANY_IP = nacaddr.IPv4("0.0.0.0/0", token="ANY")


class Term(aclgenerator.Term):
    """A single Huawei ACL Term."""

    def __init__(self, term: policy.Term):
        """Converts an model policy into an Huawei policy."""
        super().__init__(term)
        self.term = term
        if len(self.term.source_address) == 0:
            self.term.source_address = [ANY_IP]
        if len(self.term.destination_address) == 0:
            self.term.source_address = [ANY_IP]
        if len(self.term.source_port) == 0:
            self.term.source_port = [ANY_PORT]
        if len(self.term.destination_port) == 0:
            self.term.destination_port = [ANY_PORT]
        if "accept" in self.term.action:
            self.term.action = ["permit"]
        elif "deny" in self.term.action:
            self.term.action = ["deny"]

    def __str__(self):
        """Prints out a term as a string."""
        term_str = []
        rules = itertools.product(
            self.term.source_address,
            self.term.source_port,
            self.term.destination_address,
            self.term.destination_port,
            self.term.protocol,
        )
        for src_ip, src_port, dst_ip, dst_port, proto in rules:
            rule_str = [self.term.action[0], proto]
            rule_str.extend(self._AddressStr(src_ip, "source"))
            rule_str.extend(self._PortStr(src_port, "source-port"))
            rule_str.extend(self._AddressStr(dst_ip, "destination"))
            rule_str.extend(self._PortStr(dst_port, "destination-port"))
            term_str.append(" ".join(rule_str))
        return "\n".join(term_str)

    @staticmethod
    def _AddressStr(addr, direction):
        addr_str = [direction]
        if addr == ANY_IP:
            addr_str.append("any")
        else:
            addr_str.append(str(addr.network_address))
            if addr.prefixlen == 32:
                addr_str.append("32")
            else:
                addr_str.append(str(addr.netmask))
        return addr_str

    @staticmethod
    def _PortStr(port, direction):
        if port[0] == 0 and port[1] == 65535:
            return ''
        port_str = [direction]
        if port[0] != port[1]:
            port_str.append(f"range {port[0]} {port[1]}")
        else:
            port_str.append(f"eq {port[0]}")

        return port_str


class Huawei(aclgenerator.ACLGenerator):
    """A Huawei policy object."""

    _PLATFORM = "huawei"
    SUFFIX = ".hua"
    MAX_RULE_NUM = 4294967294

    def _TranslatePolicy(self, pol, exp_info):
        self.policies = []
        current_date = datetime.datetime.utcnow().date()
        exp_info_date = current_date + datetime.timedelta(weeks=exp_info)
        for header, terms in pol.filters:
            if self._PLATFORM not in header.platforms:
                continue
            header.filter_options = header.FilterOptions(self._PLATFORM)
            header.filter_name = header.FilterName(self._PLATFORM)
            if len(header.filter_name) > 127:
                raise FilterNameLengthError(
                    f"Filter name cannot exceed 127 characters, filter name is {len(header.filter_name)} characters"
                )
            header.filter_type = "advance"
            header.step_increment = 10
            header.comment = "".join(header.comment)
            if len(header.comment) > 127:
                header.comment = header.comment[:127]
                # TODO(rankeny): What will we use for logging instead of absl?
            hp_terms = []
            for term in terms:
                hp_terms.append(Term(term))
            self.policies.append((header, hp_terms))

    @staticmethod
    def _HeaderStr(header):        
        acl_header = ''
        if header.filter_name.isdigit():
            acl_header = f"undo acl {header.filter_name}\nacl {header.filter_name}"
        else:
            acl_header = f"undo acl name {header.filter_name}\nacl name {header.filter_name} {header.filter_type}"
        acl_header = f"{acl_header}\ndescription {header.comment}\nstep {header.step_increment}"
        return acl_header

    def __str__(self):
        acl = []
        for header, terms in self.policies:
            acl.append(self._HeaderStr(header))
            for term in terms:
                acl.append(str(term))
        return "\n".join(acl)


class HuaweiPlugin(plugin.BasePlugin):
    def __init__(self):
        pass

    def RequestMetadata(self, _platformMetadata):
        return plugin.PluginMetadata(capabilities=[plugin.PluginCapability.GENERATOR])

    @property
    def generators(self):
        return {"huawei": Huawei}

"""
SNMP Client for Real Switch Integration.

Uses pysnmp to issue SNMP SET commands that move a port to the
quarantine VLAN on a real managed switch.  This is the alternative
to the simulated switch REST API.

Target MIB: CISCO-VLAN-MEMBERSHIP-MIB (vmVlan)
  OID: 1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>
  This OID controls the VLAN assignment for a given port ifIndex.

For non-Cisco switches, the Q-BRIDGE-MIB (dot1qPvid) can be used:
  OID: 1.3.6.1.2.1.17.7.1.4.5.1.1.<port>

Limitations:
  - Requires SNMP v2c write access (community string with RW).
  - SNMP v3 with authentication is recommended for production.
  - ifIndex must be known for the target port.
  - Some switches require additional MIB operations for trunk ports.
"""

from typing import Optional

from .logger import setup_logger

logger = setup_logger(__name__)

# pysnmp is optional
try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        Integer32,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        setCmd,
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    logger.warning(
        "pysnmp not installed. SNMP-based quarantine disabled. "
        "Install with: pip install pysnmp"
    )


# ── Standard OIDs ──────────────────────────────────────────────────
# Cisco VLAN Membership MIB — vmVlan
CISCO_VM_VLAN_OID = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
# Q-BRIDGE-MIB — dot1qPvid (generic)
QBRIDGE_PVID_OID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
# IF-MIB — ifDescr (for port description lookup)
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"


class SnmpClient:
    """
    SNMP client for VLAN management on a managed switch.

    Supports SNMP v2c SET operations to change port VLAN assignments.
    """

    def __init__(
        self,
        host: str = "192.168.100.1",
        port: int = 161,
        community: str = "private",
        use_cisco_mib: bool = True,
    ):
        self._host = host
        self._port = port
        self._community = community
        self._base_oid = CISCO_VM_VLAN_OID if use_cisco_mib else QBRIDGE_PVID_OID
        self._engine = SnmpEngine() if PYSNMP_AVAILABLE else None

    def set_port_vlan(self, if_index: int, vlan_id: int) -> bool:
        """
        Set the VLAN for a port via SNMP SET.

        Args:
            if_index: The SNMP ifIndex of the switch port.
            vlan_id: The target VLAN ID.

        Returns:
            True if the SNMP SET succeeded.
        """
        if not PYSNMP_AVAILABLE:
            logger.error("pysnmp not available — cannot execute SNMP SET")
            return False

        oid = f"{self._base_oid}.{if_index}"
        logger.info(
            f"SNMP SET: {self._host} OID={oid} VALUE={vlan_id} "
            f"(community={self._community})"
        )

        try:
            error_indication, error_status, error_index, var_binds = next(
                setCmd(
                    self._engine,
                    CommunityData(self._community),
                    UdpTransportTarget((self._host, self._port), timeout=5, retries=2),
                    ContextData(),
                    ObjectType(
                        ObjectIdentity(oid),
                        Integer32(vlan_id),
                    ),
                )
            )

            if error_indication:
                logger.error(f"SNMP error indication: {error_indication}")
                return False
            if error_status:
                logger.error(
                    f"SNMP error: {error_status.prettyPrint()} "
                    f"at {error_index and var_binds[int(error_index) - 1][0] or '?'}"
                )
                return False

            logger.info(
                f"SNMP SET success: ifIndex {if_index} -> VLAN {vlan_id}"
            )
            return True

        except Exception as e:
            logger.error(f"SNMP SET failed: {e}")
            return False

    def get_port_vlan(self, if_index: int) -> Optional[int]:
        """
        Query the current VLAN assignment for a port.

        Returns:
            The current VLAN ID, or None on failure.
        """
        if not PYSNMP_AVAILABLE:
            return None

        oid = f"{self._base_oid}.{if_index}"

        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    self._engine,
                    CommunityData(self._community),
                    UdpTransportTarget((self._host, self._port), timeout=5, retries=2),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )

            if error_indication or error_status:
                return None

            for oid_val, val in var_binds:
                return int(val)

        except Exception as e:
            logger.error(f"SNMP GET failed: {e}")
            return None

    def health_check(self) -> bool:
        """Quick SNMP connectivity check."""
        # Try to read sysDescr (1.3.6.1.2.1.1.1.0)
        if not PYSNMP_AVAILABLE:
            return False
        try:
            error_indication, error_status, _, _ = next(
                getCmd(
                    self._engine,
                    CommunityData(self._community),
                    UdpTransportTarget((self._host, self._port), timeout=3, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
                )
            )
            return not error_indication and not error_status
        except Exception:
            return False

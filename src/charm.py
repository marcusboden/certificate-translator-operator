#!/usr/bin/env python3
# Copyright 2026 root
# See LICENSE file for licensing details.

"""Certificate Translator charm.

Bridges the legacy OpenStack tls-certificates interface with the modern
interface used by charms such as lego, vault, and self-signed-certificates.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import ops
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
from cryptography import x509

from charms.tls_certificates_interface.v3.tls_certificates import (
    TLSCertificatesRequiresV3,
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    AllCertificatesInvalidatedEvent,
)

logger = logging.getLogger(__name__)

LEGACY_RELATION = "legacy-certificates"
MODERN_RELATION = "certificates"

# TLDs that are not valid for public CAs like Let's Encrypt.
_INTERNAL_TLDS = frozenset({".lxd", ".local", ".internal", ".lan", ".home", ".test", ".example", ".invalid", ".localhost"})


def _is_public_domain(value: str) -> bool:
    """Return True if *value* is a public DNS name suitable for a public CA.

    This rejects:
    - IP addresses
    - Single-label names (no dot)
    - Names ending in known internal TLDs
    """
    # Reject IP addresses
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    # Must look like an FQDN
    if "." not in value:
        return False
    # Reject known internal suffixes
    value_lower = value.lower()
    for tld in _INTERNAL_TLDS:
        if value_lower.endswith(tld):
            return False
    return True


class CertificateTranslatorCharm(ops.CharmBase):
    """Charm that translates between old and new tls-certificates interfaces."""

    _stored = ops.StoredState()

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(
            requests={},
            modern_ca={"ca": None, "chain": None},
        )

        # Modern side (requirer of new interface)
        self.modern_tls = TLSCertificatesRequiresV3(
            charm=self,
            relationship_name=MODERN_RELATION,
        )
        framework.observe(
            self.modern_tls.on.certificate_available,
            self._on_certificate_available,
        )
        framework.observe(
            self.modern_tls.on.certificate_expiring,
            self._on_certificate_expiring,
        )
        framework.observe(
            self.modern_tls.on.certificate_invalidated,
            self._on_certificate_invalidated,
        )
        framework.observe(
            self.modern_tls.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated,
        )

        # Legacy side (provider of old interface)
        framework.observe(
            self.on[LEGACY_RELATION].relation_joined,
            self._on_legacy_relation_joined,
        )
        framework.observe(
            self.on[LEGACY_RELATION].relation_changed,
            self._on_legacy_relation_changed,
        )
        framework.observe(
            self.on[LEGACY_RELATION].relation_broken,
            self._on_legacy_relation_broken,
        )
        framework.observe(
            self.on[LEGACY_RELATION].relation_departed,
            self._on_legacy_relation_departed,
        )

        framework.observe(
            self.on[MODERN_RELATION].relation_joined,
            self._on_modern_relation_joined,
        )

        framework.observe(self.on.config_changed, self._reconcile_status)
        framework.observe(self.on.update_status, self._reconcile_status)

    def _on_modern_relation_joined(self, event: ops.RelationEvent) -> None:
        """Modern provider is now available; forward any pending legacy requests."""
        for relation in self.model.relations[LEGACY_RELATION]:
            self._process_legacy_requests(relation)
        self._reconcile_status()

    # ------------------------------------------------------------------
    # Legacy side helpers
    # ------------------------------------------------------------------

    def _legacy_unit_name(self, unit: ops.Unit) -> str:
        """Return the legacy-formatted unit name (slashes replaced by underscores)."""
        return unit.name.replace("/", "_")

    def _read_legacy_cert_requests(self, relation: ops.Relation) -> list[dict[str, Any]]:
        """Parse cert_requests from every related unit in a legacy relation."""
        requests = []
        for unit in relation.units:
            data = relation.data[unit]
            raw = data.get("cert_requests")
            if not raw:
                continue
            try:
                cert_requests = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Invalid cert_requests JSON from %s", unit.name)
                continue
            unit_name = data.get("unit_name") or self._legacy_unit_name(unit)
            requests.append(
                {
                    "unit": unit,
                    "unit_name": unit_name,
                    "cert_requests": cert_requests,
                }
            )
        return requests

    def _request_id(self, relation_id: int, unit_name: str, cn: str) -> str:
        return f"{relation_id}/{unit_name}/{cn}"

    def _generate_keypair(self, cn: str, sans: list[str]) -> tuple[str, str]:
        """Generate an RSA private key and a CSR.

        Returns (private_key_pem, csr_pem).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        san_list: list[x509.GeneralName] = []
        for san in sans:
            try:
                san_list.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                san_list.append(x509.DNSName(san))

        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
        csr_builder = x509.CertificateSigningRequestBuilder(subject_name=subject)
        if san_list:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
        csr = csr_builder.sign(private_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        return private_key_pem, csr_pem

    def _process_legacy_requests(self, relation: ops.Relation) -> None:
        """Read legacy requests and forward them to the modern provider."""
        if not self.model.get_relation(MODERN_RELATION):
            logger.info("Modern provider not yet related; deferring requests.")
            return

        for req in self._read_legacy_cert_requests(relation):
            unit_name = req["unit_name"]
            cert_requests = req["cert_requests"]
            for cn, spec in cert_requests.items():
                # Filter out non-public CNs (e.g. .lxd, IP addresses)
                if not _is_public_domain(cn):
                    logger.info(
                        "Skipping certificate request for non-public CN %s",
                        cn,
                    )
                    continue

                sans = [s for s in spec.get("sans", []) if _is_public_domain(s)]
                req_id = self._request_id(relation.id, unit_name, cn)
                existing = self._stored.requests.get(req_id)

                if existing:
                    # If SANs changed, revoke old and recreate.
                    if existing.get("sans") == sans:
                        continue
                    self._revoke_modern_request(existing)

                private_key_pem, csr_pem = self._generate_keypair(cn, sans)
                self._stored.requests[req_id] = {
                    "legacy_relation_id": relation.id,
                    "legacy_unit_name": unit_name,
                    "cn": cn,
                    "sans": sans,
                    "private_key": private_key_pem,
                    "csr": csr_pem,
                    "certificate": None,
                    "ca": None,
                    "chain": None,
                }
                logger.info(
                    "Requesting certificate for %s (relation %s, unit %s) with SANs %s",
                    cn,
                    relation.id,
                    unit_name,
                    sans,
                )
                self.modern_tls.request_certificate_creation(
                    certificate_signing_request=csr_pem.encode(),
                    is_ca=False,
                )

    def _revoke_modern_request(self, request: dict[str, Any]) -> None:
        """Revoke a modern CSR and clean its state."""
        csr_pem = request.get("csr")
        if csr_pem:
            try:
                self.modern_tls.request_certificate_revocation(csr_pem.encode())
            except Exception:
                logger.warning("Failed to revoke CSR, continuing anyway")
        request_id = self._request_id(
            request["legacy_relation_id"],
            request["legacy_unit_name"],
            request["cn"],
        )
        if request_id in self._stored.requests:
            del self._stored.requests[request_id]

    def _publish_legacy_certs(self, relation_id: int, unit_name: str) -> None:
        """Write processed_requests, ca and chain to a legacy relation."""
        relation = self.model.get_relation(LEGACY_RELATION, relation_id)
        if not relation:
            return

        processed: dict[str, dict[str, str]] = {}
        ca_pem: str | None = None
        chain_pem: str | None = None

        prefix = f"{relation_id}/{unit_name}"
        for req_id, req in self._stored.requests.items():
            if not req_id.startswith(prefix):
                continue
            if req.get("certificate"):
                processed[req["cn"]] = {
                    "cert": req["certificate"],
                    "key": req["private_key"],
                }
                if req.get("ca"):
                    ca_pem = req["ca"]
                if req.get("chain"):
                    chain_pem = req["chain"]

        if not processed:
            return

        relation.data[self.unit][f"{unit_name}.processed_requests"] = json.dumps(processed)
        if ca_pem:
            relation.data[self.unit]["ca"] = ca_pem
        if chain_pem:
            relation.data[self.unit]["chain"] = chain_pem

    # ------------------------------------------------------------------
    # Modern side handlers
    # ------------------------------------------------------------------

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """A certificate was returned by the modern provider."""
        csr_pem = event.certificate_signing_request.strip()
        # Match CSR to stored request.
        for req_id, req in self._stored.requests.items():
            if req.get("csr", "").strip() == csr_pem:
                req["certificate"] = str(event.certificate)
                req["ca"] = str(event.ca)
                if event.chain:
                    # Old interface expects a single PEM string for the chain.
                    req["chain"] = "\n".join(str(c) for c in event.chain)
                else:
                    req["chain"] = ""
                logger.info(
                    "Certificate received for %s (relation %s, unit %s)",
                    req["cn"],
                    req["legacy_relation_id"],
                    req["legacy_unit_name"],
                )
                self._publish_legacy_certs(
                    req["legacy_relation_id"],
                    req["legacy_unit_name"],
                )
                self._reconcile_status()
                return

        logger.warning("Received certificate for an unknown CSR")

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """A certificate is about to expire; request renewal."""
        old_csr_pem = event.certificate_signing_request.strip()
        for req_id, req in self._stored.requests.items():
            if req.get("csr", "").strip() == old_csr_pem:
                cn = req["cn"]
                sans = req["sans"]
                private_key_pem = req["private_key"]
                # Regenerate CSR using the same private key.
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(), password=None
                )
                subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
                csr_builder = x509.CertificateSigningRequestBuilder(subject_name=subject)
                san_list: list[x509.GeneralName] = []
                for san in sans:
                    try:
                        san_list.append(x509.IPAddress(ipaddress.ip_address(san)))
                    except ValueError:
                        san_list.append(x509.DNSName(san))
                if san_list:
                    csr_builder = csr_builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False,
                    )
                new_csr = csr_builder.sign(private_key, hashes.SHA256())
                new_csr_pem = new_csr.public_bytes(serialization.Encoding.PEM).decode()
                req["csr"] = new_csr_pem
                req["certificate"] = None
                logger.info(
                    "Renewing certificate for %s (relation %s, unit %s)",
                    cn,
                    req["legacy_relation_id"],
                    req["legacy_unit_name"],
                )
                self.modern_tls.request_certificate_renewal(
                    old_certificate_signing_request=old_csr_pem.encode(),
                    new_certificate_signing_request=new_csr_pem.encode(),
                )
                return

        logger.warning("Received expiry notice for an unknown CSR")

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """A certificate was revoked or became invalid."""
        csr_pem = event.certificate_signing_request.strip()
        for req_id, req in list(self._stored.requests.items()):
            if req.get("csr", "").strip() == csr_pem:
                req["certificate"] = None
                req["ca"] = None
                req["chain"] = None
                self._publish_legacy_certs(
                    req["legacy_relation_id"],
                    req["legacy_unit_name"],
                )
                return

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent) -> None:
        """The modern relation was broken; invalidate all legacy certificates."""
        for req_id, req in list(self._stored.requests.items()):
            req["certificate"] = None
            req["ca"] = None
            req["chain"] = None
            self._publish_legacy_certs(
                req["legacy_relation_id"],
                req["legacy_unit_name"],
            )
        self._reconcile_status()

    # ------------------------------------------------------------------
    # Legacy side handlers
    # ------------------------------------------------------------------

    def _on_legacy_relation_joined(self, event: ops.RelationEvent) -> None:
        self._process_legacy_requests(event.relation)
        self._reconcile_status()

    def _on_legacy_relation_changed(self, event: ops.RelationEvent) -> None:
        self._process_legacy_requests(event.relation)
        self._reconcile_status()

    def _on_legacy_relation_departed(self, event: ops.RelationEvent) -> None:
        if not event.unit:
            return
        unit_name = self._legacy_unit_name(event.unit)
        self._cleanup_legacy_unit(event.relation.id, unit_name)
        self._reconcile_status()

    def _on_legacy_relation_broken(self, event: ops.RelationEvent) -> None:
        self._cleanup_legacy_relation(event.relation.id)
        self._reconcile_status()

    def _cleanup_legacy_unit(self, relation_id: int, unit_name: str) -> None:
        """Remove all requests for a departed legacy unit."""
        prefix = f"{relation_id}/{unit_name}/"
        for req_id in list(self._stored.requests.keys()):
            if req_id.startswith(prefix):
                req = self._stored.requests[req_id]
                self._revoke_modern_request(req)

    def _cleanup_legacy_relation(self, relation_id: int) -> None:
        """Remove all requests for a broken legacy relation."""
        prefix = f"{relation_id}/"
        for req_id in list(self._stored.requests.keys()):
            if req_id.startswith(prefix):
                req = self._stored.requests[req_id]
                self._revoke_modern_request(req)

    # ------------------------------------------------------------------
    # Status reconciliation
    # ------------------------------------------------------------------

    def _reconcile_status(self, event: ops.EventBase | None = None) -> None:
        """Set unit status based on current state."""
        if not self.model.get_relation(MODERN_RELATION):
            self.unit.status = ops.BlockedStatus("missing certificates relation")
            return

        pending = 0
        for req in self._stored.requests.values():
            if not req.get("certificate"):
                pending += 1

        if pending:
            self.unit.status = ops.MaintenanceStatus(
                f"awaiting {pending} certificate(s)"
            )
            return

        self.unit.status = ops.ActiveStatus()


if __name__ == "__main__":  # pragma: nocover
    ops.main(CertificateTranslatorCharm)

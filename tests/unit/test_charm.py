# Copyright 2026 root
# See LICENSE file for licensing details.

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ops import testing

from charm import CertificateTranslatorCharm

LEGACY_RELATION = "legacy-certificates"
MODERN_RELATION = "certificates"


def _generate_test_cert(cn: str = "keystone.example.com", sans: list[str] | None = None):
    """Generate a self-signed cert and CSR for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    csr_builder = x509.CertificateSigningRequestBuilder(subject_name=subject)
    if sans:
        san_list = []
        for san in sans:
            try:
                import ipaddress
                san_list.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                san_list.append(x509.DNSName(san))
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName(san_list), critical=False
        )
    csr = csr_builder.sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem, cert_pem


@pytest.fixture
def ctx():
    return testing.Context(CertificateTranslatorCharm)


def _stored_state(data):
    return testing.StoredState(
        name="_stored",
        owner_path="CertificateTranslatorCharm",
        content=data,
    )


class TestLegacyToModern:
    def test_legacy_relation_joined_creates_modern_csr(self, ctx):
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
        )
        legacy = testing.Relation(
            endpoint=LEGACY_RELATION,
            interface="tls-certificates",
            remote_app_name="keystone",
            remote_units_data={
                0: {
                    "cert_requests": json.dumps(
                        {"keystone.example.com": {"sans": ["10.0.0.1"]}}
                    ),
                    "unit_name": "keystone_0",
                }
            },
        )
        state = testing.State(
            relations={modern, legacy},
        )
        out = ctx.run(
            ctx.on.relation_changed(legacy, remote_unit=0),
            state,
        )
        modern_rel = out.get_relation(modern.id)
        raw = modern_rel.local_unit_data.get("certificate_signing_requests")
        assert raw is not None
        csrs = json.loads(raw)
        assert len(csrs) == 1
        assert "certificate_signing_request" in csrs[0]

    def test_legacy_cert_requests_parsed(self, ctx):
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
        )
        legacy = testing.Relation(
            endpoint=LEGACY_RELATION,
            interface="tls-certificates",
            remote_app_name="keystone",
            remote_units_data={
                0: {
                    "cert_requests": json.dumps(
                        {
                            "keystone.example.com": {"sans": ["10.0.0.1"]},
                            "keystone-alt.example.com": {"sans": ["10.0.0.2"]},
                        }
                    ),
                    "unit_name": "keystone_0",
                }
            },
        )
        state = testing.State(
            relations={modern, legacy},
        )
        out = ctx.run(
            ctx.on.relation_changed(legacy, remote_unit=0),
            state,
        )
        modern_rel = out.get_relation(modern.id)
        raw = modern_rel.local_unit_data.get("certificate_signing_requests")
        assert raw is not None
        csrs = json.loads(raw)
        assert len(csrs) == 2


class TestModernToLegacy:
    def test_certificate_available_publishes_legacy_data(self, ctx):
        key_pem, csr_pem, cert_pem = _generate_test_cert(
            cn="keystone.example.com", sans=["10.0.0.1"]
        )
        legacy = testing.Relation(
            endpoint=LEGACY_RELATION,
            interface="tls-certificates",
            remote_app_name="keystone",
        )
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
            local_unit_data={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr_pem, "ca": False}]
                )
            },
            remote_app_data={
                "certificates": json.dumps(
                    [
                        {
                            "certificate": cert_pem,
                            "certificate_signing_request": csr_pem,
                            "ca": cert_pem,
                            "chain": [cert_pem],
                        }
                    ]
                )
            },
        )
        state = testing.State(
            relations={modern, legacy},
            stored_states=[
                _stored_state({
                    "requests": {
                        f"{legacy.id}/keystone_0/keystone.example.com": {
                            "legacy_relation_id": legacy.id,
                            "legacy_unit_name": "keystone_0",
                            "cn": "keystone.example.com",
                            "sans": ["10.0.0.1"],
                            "private_key": key_pem,
                            "csr": csr_pem,
                            "certificate": None,
                            "ca": None,
                            "chain": None,
                        }
                    },
                    "modern_ca": {"ca": None, "chain": None},
                })
            ],
        )
        out = ctx.run(
            ctx.on.relation_changed(modern),
            state,
        )
        legacy_rel = out.get_relation(legacy.id)
        assert "keystone_0.processed_requests" in legacy_rel.local_unit_data
        processed = json.loads(legacy_rel.local_unit_data["keystone_0.processed_requests"])
        assert "keystone.example.com" in processed
        assert processed["keystone.example.com"]["cert"] == cert_pem
        assert processed["keystone.example.com"]["key"] == key_pem
        assert legacy_rel.local_unit_data.get("ca") == cert_pem
        assert legacy_rel.local_unit_data.get("chain") == cert_pem


class TestCleanup:
    def test_legacy_relation_broken_cleans_up(self, ctx):
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
        )
        legacy = testing.Relation(
            endpoint=LEGACY_RELATION,
            interface="tls-certificates",
            remote_app_name="keystone",
            remote_units_data={
                0: {
                    "cert_requests": json.dumps(
                        {"keystone.example.com": {"sans": ["10.0.0.1"]}}
                    ),
                    "unit_name": "keystone_0",
                }
            },
        )
        state = testing.State(
            relations={modern, legacy},
        )
        # First, process the legacy request
        out = ctx.run(
            ctx.on.relation_changed(legacy, remote_unit=0),
            state,
        )
        modern_rel = out.get_relation(modern.id)
        assert "certificate_signing_requests" in modern_rel.local_unit_data
        # Then break the legacy relation
        out2 = ctx.run(ctx.on.relation_broken(legacy), out)
        modern_rel2 = out2.get_relation(modern.id)
        csrs = json.loads(modern_rel2.local_unit_data.get("certificate_signing_requests", "[]"))
        assert len(csrs) == 0


class TestStatus:
    def test_blocked_without_modern_relation(self, ctx):
        legacy = testing.Relation(
            endpoint=LEGACY_RELATION,
            interface="tls-certificates",
            remote_app_name="keystone",
        )
        state = testing.State(relations={legacy})
        out = ctx.run(ctx.on.config_changed(), state)
        assert out.unit_status == testing.BlockedStatus("missing certificates relation")

    def test_active_when_all_certs_ready(self, ctx):
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
        )
        state = testing.State(
            relations={modern},
            stored_states=[
                _stored_state({
                    "requests": {},
                    "modern_ca": {"ca": None, "chain": None},
                })
            ],
        )
        out = ctx.run(ctx.on.config_changed(), state)
        assert out.unit_status == testing.ActiveStatus()

    def test_maintenance_when_pending_certs(self, ctx):
        modern = testing.Relation(
            endpoint=MODERN_RELATION,
            interface="tls-certificates",
            remote_app_name="lego",
        )
        state = testing.State(
            relations={modern},
            stored_states=[
                _stored_state({
                    "requests": {
                        "1/keystone_0/keystone.example.com": {
                            "legacy_relation_id": 1,
                            "legacy_unit_name": "keystone_0",
                            "cn": "keystone.example.com",
                            "sans": ["10.0.0.1"],
                            "private_key": "FAKE_KEY",
                            "csr": "FAKE_CSR",
                            "certificate": None,
                            "ca": None,
                            "chain": None,
                        }
                    },
                    "modern_ca": {"ca": None, "chain": None},
                })
            ],
        )
        out = ctx.run(ctx.on.config_changed(), state)
        assert out.unit_status == testing.MaintenanceStatus("awaiting 1 certificate(s)")

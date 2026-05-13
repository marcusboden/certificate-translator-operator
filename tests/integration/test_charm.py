# Copyright 2026 root
# See LICENSE file for licensing details.
#
# The integration tests use the Jubilant library. See https://documentation.ubuntu.com/jubilant/
# To learn more about testing, see https://documentation.ubuntu.com/ops/latest/explanation/testing/

import logging
import pathlib

import jubilant
import pytest

logger = logging.getLogger(__name__)


def test_deploy_with_provider(charm: pathlib.Path, juju: jubilant.Juju):
    """Deploy the charm with a modern TLS provider and verify it goes active."""
    juju.deploy("self-signed-certificates", app="self-signed-certificates", channel="1/stable")
    juju.deploy(charm.resolve(), app="certificate-translator")
    juju.relate("certificate-translator:certificates", "self-signed-certificates:certificates")
    juju.wait(jubilant.all_active)

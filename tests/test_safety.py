"""Safety kernel and operator integration tests."""

from __future__ import annotations

from uuid import uuid4

import pytest

from nexus.core.types import (
    Asset,
    AssetType,
    AttackPath,
    AttackStep,
    CampaignMode,
    Scope,
    Severity,
)
from nexus.safety.kernel import SafetyKernel
from nexus.agents.operator import OperatorAgent


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def test_scope_ip_allow():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.OBSERVE)
    assert kernel.check_scope("10.0.0.5") is True
    assert kernel.check_scope("10.0.0.5:8080") is True
    assert kernel.check_scope("192.168.1.1") is False


def test_scope_domain_allow():
    scope = Scope(
        name="test",
        domains=["lab.example.com"],
        hostnames=["jump.lab.example.com"],
    )
    kernel = SafetyKernel(scope, CampaignMode.OBSERVE)
    assert kernel.check_scope("lab.example.com") is True
    assert kernel.check_scope("api.lab.example.com") is True
    assert kernel.check_scope("jump.lab.example.com") is True
    assert kernel.check_scope("evil.example.com") is False


def test_scope_excluded_ip():
    scope = Scope(
        name="test",
        ip_ranges=["10.0.0.0/24"],
        excluded_ips=["10.0.0.1"],
    )
    kernel = SafetyKernel(scope, CampaignMode.OBSERVE)
    assert kernel.check_scope("10.0.0.5") is True
    assert kernel.check_scope("10.0.0.1") is False


# ---------------------------------------------------------------------------
# Payload sanitisation
# ---------------------------------------------------------------------------

def test_destructive_payload_blocked():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)
    with pytest.raises(PermissionError):
        kernel.sanitize_payload("rm -rf /")


def test_observe_mode_blocks_payload():
    scope = Scope(name="test")
    kernel = SafetyKernel(scope, CampaignMode.OBSERVE)
    with pytest.raises(PermissionError):
        kernel.sanitize_payload("echo hello")


def test_safe_payload_passes():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)
    result = kernel.sanitize_payload("Non-destructive PoC (config read)")
    assert "config read" in result


# ---------------------------------------------------------------------------
# Logging / severity mapping (regression for TypeError)
# ---------------------------------------------------------------------------

def test_record_event_does_not_raise_type_error():
    """Regression: logger.log must receive int level, not Severity.value str."""
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)
    # This previously raised: TypeError: '<' not supported between instances of 'str' and 'int'
    kernel._record_event("test_event", Severity.HIGH, "unit-test message")
    events = kernel.get_safety_events()
    assert len(events) == 1
    assert events[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Operator target resolution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_operator_resolves_asset_address():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)

    asset = Asset(
        type=AssetType.HOST,
        address="10.0.0.5",
        hostname=None,
        ports=[80],
    )
    step = AttackStep(
        technique_id="T1190",
        name="Test step",
        description="unit test",
        target_asset_id=asset.id,
        payload_summary="Non-destructive PoC (config read / math challenge)",
    )
    path = AttackPath(name="test-path", steps=[step])

    operator = OperatorAgent({})
    result_paths = await operator.execute_safe(
        [path], kernel, CampaignMode.PROVE, assets=[asset]
    )
    assert result_paths[0].success is True
    assert result_paths[0].steps[0].evidence.get("target") == "10.0.0.5"


@pytest.mark.asyncio
async def test_operator_blocks_out_of_scope_target():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)

    asset = Asset(
        type=AssetType.HOST,
        address="192.168.99.1",  # outside scope
        ports=[80],
    )
    step = AttackStep(
        technique_id="T1190",
        name="OOS step",
        description="unit test",
        target_asset_id=asset.id,
        payload_summary="Non-destructive PoC",
    )
    path = AttackPath(name="oos-path", steps=[step])

    operator = OperatorAgent({})
    result_paths = await operator.execute_safe(
        [path], kernel, CampaignMode.PROVE, assets=[asset]
    )
    assert result_paths[0].success is False
    assert result_paths[0].steps[0].evidence.get("reason") == "safety_blocked"
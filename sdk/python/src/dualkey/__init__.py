from __future__ import annotations

from importlib import import_module

__all__ = [
    "ActionEnvelope",
    "ApprovalDecision",
    "AuthorizationResult",
    "BrowserUseGuard",
    "DualKey",
    "OpenHandsGuard",
    "Policy",
    "PolicyCheck",
    "PolicyExplanation",
    "PolicyOutcome",
    "PolicyRuleTrace",
    "ProtectedAgent",
    "Receipt",
    "ReceiptQuery",
    "ReceiptSettings",
    "ReceiptSigner",
    "ReceiptStore",
    "ReceiptTrace",
    "build_receipt",
    "guard_browser_use_tools",
    "guard_openhands_agent",
    "guard_openhands_conversation",
    "guard_openhands_tools",
    "load_policy",
    "protect",
    "sign_bundle_manifest_payload",
    "verify_bundle_manifest_payload",
    "verify_receipt_payload",
]

_EXPORT_MAP = {
    "ActionEnvelope": ("dualkey.models", "ActionEnvelope"),
    "ApprovalDecision": ("dualkey.models", "ApprovalDecision"),
    "AuthorizationResult": ("dualkey.models", "AuthorizationResult"),
    "BrowserUseGuard": ("dualkey.browser_use_adapter", "BrowserUseGuard"),
    "DualKey": ("dualkey.engine", "DualKey"),
    "OpenHandsGuard": ("dualkey.openhands_adapter", "OpenHandsGuard"),
    "Policy": ("dualkey.policy", "Policy"),
    "PolicyCheck": ("dualkey.policy", "PolicyCheck"),
    "PolicyExplanation": ("dualkey.policy", "PolicyExplanation"),
    "PolicyOutcome": ("dualkey.models", "PolicyOutcome"),
    "PolicyRuleTrace": ("dualkey.policy", "PolicyRuleTrace"),
    "ProtectedAgent": ("dualkey.engine", "ProtectedAgent"),
    "Receipt": ("dualkey.models", "Receipt"),
    "ReceiptQuery": ("dualkey.receipts", "ReceiptQuery"),
    "ReceiptSettings": ("dualkey.receipts", "ReceiptSettings"),
    "ReceiptSigner": ("dualkey.receipts", "ReceiptSigner"),
    "ReceiptStore": ("dualkey.receipts", "ReceiptStore"),
    "ReceiptTrace": ("dualkey.receipts", "ReceiptTrace"),
    "build_receipt": ("dualkey.receipts", "build_receipt"),
    "guard_browser_use_tools": ("dualkey.browser_use_adapter", "guard_browser_use_tools"),
    "guard_openhands_agent": ("dualkey.openhands_adapter", "guard_openhands_agent"),
    "guard_openhands_conversation": ("dualkey.openhands_adapter", "guard_openhands_conversation"),
    "guard_openhands_tools": ("dualkey.openhands_adapter", "guard_openhands_tools"),
    "load_policy": ("dualkey.policy", "load_policy"),
    "protect": ("dualkey.engine", "protect"),
    "sign_bundle_manifest_payload": ("dualkey.receipts", "sign_bundle_manifest_payload"),
    "verify_bundle_manifest_payload": ("dualkey.receipts", "verify_bundle_manifest_payload"),
    "verify_receipt_payload": ("dualkey.receipts", "verify_receipt_payload"),
}


def __getattr__(name: str):
    try:
        module_name, attribute_name = _EXPORT_MAP[name]
    except KeyError as exc:
        raise AttributeError(f"module 'dualkey' has no attribute {name!r}") from exc
    module = import_module(module_name)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value

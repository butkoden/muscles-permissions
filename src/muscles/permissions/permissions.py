from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence


class ServiceResolver(Protocol):
    def resolve(self, interface: type) -> Any: ...


@dataclass(frozen=True)
class PermissionContext:
    subject: Any = None
    resource: Any = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    services: ServiceResolver | None = None

    def resolve(self, interface: type) -> Any:
        if self.services is None:
            raise LookupError("No service resolver is available in the permission context")
        return self.services.resolve(interface)


@dataclass(frozen=True)
class Policy:
    title: str
    handler: Callable[[PermissionContext], bool]


@dataclass(frozen=True)
class PolicyExtension:
    permission_id: str
    policy_id: str
    policy: Policy

    def __post_init__(self) -> None:
        if (not isinstance(self.permission_id, str) or not self.permission_id
                or not isinstance(self.policy_id, str) or not self.policy_id
                or not isinstance(self.policy, Policy) or not callable(self.policy.handler)):
            raise ValueError("Invalid permission policy extension")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    matched_policy: str | None = None


@dataclass(frozen=True)
class Permission:
    id: str
    title: str
    policies: Mapping[str, Policy]
    default_policies: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id or not isinstance(self.title, str) or not self.title:
            raise ValueError("Permission id and title are required")
        policies = dict(self.policies)
        if any(not name or not isinstance(policy, Policy) or not callable(policy.handler)
               for name, policy in policies.items()):
            raise ValueError("Each policy must have an id and callable handler")
        if isinstance(self.default_policies, str):
            raise TypeError("default_policies must be a sequence of policy ids")
        defaults = tuple(self.default_policies)
        if any(name not in policies for name in defaults):
            raise ValueError("Default policies must be declared by the permission")
        object.__setattr__(self, "policies", MappingProxyType(policies))
        object.__setattr__(self, "default_policies", defaults)

    def get_policies(self) -> Mapping[str, Policy]:
        return self.policies

    def evaluate(self, context: PermissionContext, policies: Sequence[str] | None = None) -> Decision:
        if isinstance(policies, str):
            raise TypeError("policies must be a sequence of policy ids")
        selected = self.default_policies if policies is None else tuple(policies)
        if any(name not in self.policies for name in selected):
            raise ValueError("Unknown permission policy")
        for name in selected:
            if self.policies[name].handler(context) is True:
                return Decision(allowed=True, matched_policy=name)
        return Decision(allowed=False)


class PermissionRegistry:
    def __init__(self, permissions: dict[str, Permission] | None = None,
                 extensions: dict[str, dict[str, Policy]] | None = None) -> None:
        self._permissions = permissions if permissions is not None else {}
        self._extensions = extensions if extensions is not None else {}

    def register(self, permission: Permission) -> None:
        if not isinstance(permission, Permission):
            raise TypeError("Expected a Permission declaration")
        if permission.id in self._permissions:
            raise ValueError(f"Duplicate permission: {permission.id}")
        if set(permission.policies) & set(self._extensions.get(permission.id, {})):
            raise ValueError(f"Duplicate permission policy: {permission.id}")
        self._permissions[permission.id] = permission

    def register_policy(self, permission_id: str, policy_id: str, policy: Policy) -> None:
        extension = PolicyExtension(permission_id, policy_id, policy)
        permission = self._permissions[extension.permission_id]
        existing = self._extensions.get(extension.permission_id, {})
        if extension.policy_id in permission.policies or extension.policy_id in existing:
            raise ValueError(f"Duplicate permission policy: {permission_id}:{policy_id}")
        self._extensions.setdefault(permission_id, {})[policy_id] = policy

    def get(self, permission_id: str) -> Permission:
        permission = self._permissions[permission_id]
        extensions = self._extensions.get(permission_id, {})
        if not extensions:
            return permission
        return replace(permission, policies={**permission.policies, **extensions})

    def list(self) -> tuple[Permission, ...]:
        return tuple(self.get(permission_id) for permission_id in self._permissions)

    def validate(self) -> None:
        missing = set(self._extensions) - set(self._permissions)
        if missing:
            raise ValueError(f"Unknown permissions for policy extensions: {sorted(missing)}")


class PolicySource(Protocol):
    def get_policies(self, permission: Permission, context: PermissionContext) -> Sequence[str] | None:
        """Return assigned policies, or None to use the permission defaults."""
        ...


@dataclass(frozen=True)
class PermissionResourceHandler:
    """Package-owned resolver and action permissions for a resource type."""

    resource_type: str
    permissions: Mapping[str, str]
    resolver: Callable[[str, PermissionContext], Any | None]

    def __post_init__(self) -> None:
        if not isinstance(self.resource_type, str) or not self.resource_type:
            raise ValueError("Permission resource type is required")
        if not callable(self.resolver):
            raise ValueError("Permission resource resolver must be callable")
        permissions = dict(self.permissions)
        if not permissions or any(
            not isinstance(action, str) or not action
            or not isinstance(permission_id, str) or not permission_id
            for action, permission_id in permissions.items()
        ):
            raise ValueError("Permission resource handler must declare action permissions")
        object.__setattr__(self, "permissions", MappingProxyType(permissions))


class PermissionResourceRegistry:
    """Registry for package-owned resource loading and action permission mapping."""

    def __init__(
        self,
        handlers: Mapping[str, PermissionResourceHandler] | Iterable[PermissionResourceHandler] | None = None,
    ) -> None:
        self._handlers = handlers if isinstance(handlers, dict) else {}
        if handlers is not None and not isinstance(handlers, Mapping):
            for handler in handlers:
                self.register(handler)
        elif handlers is not None and not isinstance(handlers, dict):
            self._handlers.update(handlers)

    def register(self, handler: PermissionResourceHandler) -> None:
        if not isinstance(handler, PermissionResourceHandler):
            raise TypeError("Expected a PermissionResourceHandler")
        if handler.resource_type in self._handlers:
            raise ValueError(f"Duplicate permission resource handler: {handler.resource_type}")
        self._handlers[handler.resource_type] = handler

    def get(self, resource_type: str) -> PermissionResourceHandler | None:
        return self._handlers.get(resource_type)

    def validate(self, permissions: PermissionRegistry) -> None:
        missing = set()
        for handler in self._handlers.values():
            for permission_id in handler.permissions.values():
                try:
                    permissions.get(permission_id)
                except KeyError:
                    missing.add(permission_id)
        if missing:
            raise ValueError(f"Unknown permissions for resource handlers: {sorted(missing)}")


class PermissionDenied(PermissionError):
    pass


class PermissionEvaluator:
    def __init__(self, registry: PermissionRegistry, source: PolicySource | None = None,
                 services: ServiceResolver | None = None) -> None:
        self.registry = registry
        self.source = source
        self.services = services

    def evaluate(self, permission: Permission | str, context: PermissionContext | None = None,
                 policies: Sequence[str] | None = None, *, subject: Any = None,
                 resource: Any = None, attributes: Mapping[str, Any] | None = None) -> Decision:
        if context is None:
            context = PermissionContext(subject, resource, attributes or {}, self.services)
        elif subject is not None or resource is not None or attributes is not None:
            raise ValueError("Provide either context or subject/resource/attributes")
        elif context.services is None and self.services is not None:
            context = replace(context, services=self.services)
        permission_id = permission.id if isinstance(permission, Permission) else permission
        definition = self.registry.get(permission_id)
        assigned = self.source.get_policies(definition, context) if self.source is not None else None
        if policies is None:
            selected = assigned
        elif assigned is None:
            selected = policies
        else:
            if isinstance(policies, str):
                raise TypeError("policies must be a sequence of policy ids")
            explicit = tuple(policies)
            if any(policy_id not in definition.policies for policy_id in explicit):
                raise ValueError("Unknown permission policy")
            selected_ids = set(assigned)
            selected = tuple(policy_id for policy_id in explicit if policy_id in selected_ids)
        return definition.evaluate(context, selected)

    def require(self, permission: Permission | str, context: PermissionContext,
                policies: Sequence[str] | None = None) -> Decision:
        decision = self.evaluate(permission, context, policies)
        if not decision.allowed:
            raise PermissionDenied(f"Permission denied: {permission.id if isinstance(permission, Permission) else permission}")
        return decision

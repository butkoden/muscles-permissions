import pytest

from muscles.permissions import (Permission, PermissionContext, PermissionDenied,
                                 PermissionEvaluator, PermissionRegistry,
                                 PermissionResourceHandler, PermissionResourceRegistry, Policy)


def test_default_and_selected_policies_use_or_and_empty_denies():
    permission = Permission(
        id="documents:delete",
        title="Delete document",
        policies={
            "owner": Policy("Owner", lambda ctx: ctx.subject == ctx.resource),
            "member": Policy("Member", lambda ctx: ctx.attributes.get("member") is True),
        },
        default_policies=("owner",),
    )
    context = PermissionContext(subject="alice", resource="bob", attributes={"member": True})

    assert not permission.evaluate(context).allowed
    assert permission.evaluate(context, ["owner", "member"]).matched_policy == "member"
    assert not permission.evaluate(context, []).allowed
    with pytest.raises(ValueError):
        permission.evaluate(context, ["member", "unknown"])


def test_registry_rejects_duplicate_ids():
    registry = PermissionRegistry()
    permission = Permission(id="documents:delete", title="Delete", policies={})
    registry.register(permission)
    assert registry.get(permission.id) is permission
    with pytest.raises(ValueError):
        registry.register(permission)


def test_undeclared_default_is_rejected():
    with pytest.raises(ValueError):
        Permission(id="documents:delete", title="Delete", policies={}, default_policies=("owner",))


def test_evaluator_uses_source_then_defaults_and_denies_explicit_empty():
    class Source:
        def get_policies(self, permission, context):
            return context.attributes.get("assigned")

    registry = PermissionRegistry()
    permission = Permission("documents:delete", "Delete", {
        "owner": Policy("Owner", lambda ctx: ctx.subject == ctx.resource),
        "member": Policy("Member", lambda ctx: True),
    }, ("owner",))
    registry.register(permission)
    evaluator = PermissionEvaluator(registry, Source())
    assert evaluator.require(permission.id, PermissionContext("alice", "alice")).allowed
    assert evaluator.require(permission, PermissionContext("alice", "bob", {"assigned": ["member"]})).allowed
    with pytest.raises(PermissionDenied):
        evaluator.require(permission, PermissionContext("alice", "alice", {"assigned": []}))
    with pytest.raises(KeyError):
        evaluator.require("unknown", PermissionContext())


def test_handlers_use_shared_service_and_stop_after_first_allow():
    class RoleReader:
        pass

    class Services:
        def resolve(self, interface):
            assert interface is RoleReader
            return lambda user, role: (user, role) == ("alice", "editor")

    calls = []

    def owner(context):
        calls.append("owner")
        return context.resource == context.subject

    def editor(context):
        calls.append("editor")
        return context.resolve(RoleReader)(context.subject, "editor")

    def moderator(context):
        calls.append("moderator")
        return True

    permission = Permission("documents:update", "Update", {
        "owner": Policy("Owner", owner),
        "editor": Policy("Editor", editor),
        "moderator": Policy("Moderator", moderator),
    })
    registry = PermissionRegistry()
    registry.register(permission)
    evaluator = PermissionEvaluator(registry, services=Services())
    decision = evaluator.evaluate(permission=permission, policies=["owner", "editor", "moderator"],
                                  subject="alice", resource="bob")
    assert decision.allowed and decision.matched_policy == "editor"
    assert calls == ["owner", "editor"]


def test_handler_errors_are_not_converted_to_allow():
    def broken(context):
        raise RuntimeError("role service unavailable")

    permission = Permission("documents:update", "Update", {
        "broken": Policy("Broken", broken),
        "allow": Policy("Allow", lambda context: True),
    })
    with pytest.raises(RuntimeError, match="role service unavailable"):
        permission.evaluate(PermissionContext(), ["broken", "allow"])


def test_register_policy_exposes_extension_and_rejects_conflicts():
    registry = PermissionRegistry()
    permission = Permission("documents:update", "Update", {"owner": Policy("Owner", lambda ctx: False)})
    registry.register(permission)
    registry.register_policy(permission.id, "editor", Policy("Editor", lambda ctx: True))
    assert set(registry.get(permission.id).get_policies()) == {"owner", "editor"}
    assert registry.list()[0].evaluate(PermissionContext(), ["editor"]).allowed
    with pytest.raises(ValueError, match="Duplicate permission policy"):
        registry.register_policy(permission.id, "owner", Policy("Another owner", lambda ctx: True))
    with pytest.raises(ValueError, match="Duplicate permission policy"):
        registry.register_policy(permission.id, "editor", Policy("Another editor", lambda ctx: True))
    with pytest.raises(KeyError):
        registry.register_policy("missing:read", "editor", Policy("Editor", lambda ctx: True))


def test_permission_resource_registry_registers_handlers_and_rejects_duplicates():
    resolver = lambda resource_uid, context: {"uid": resource_uid}
    handler = PermissionResourceHandler(
        resource_type="notes:note",
        permissions={"attach": "notes:notes.update"},
        resolver=resolver,
    )
    registry = PermissionResourceRegistry()

    registry.register(handler)

    assert registry.get("notes:note") is handler
    assert registry.get("missing:resource") is None
    with pytest.raises(ValueError, match="Duplicate permission resource handler"):
        registry.register(handler)
    with pytest.raises(TypeError, match="Expected a PermissionResourceHandler"):
        registry.register(object())


def test_permission_resource_handler_requires_permission_and_callable_resolver():
    with pytest.raises(ValueError, match="action permissions"):
        PermissionResourceHandler("notes:note", {}, lambda uid, context: None)
    with pytest.raises(ValueError, match="resolver must be callable"):
        PermissionResourceHandler("notes:note", {"attach": "notes:update"}, None)

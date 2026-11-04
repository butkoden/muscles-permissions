import pytest

from muscles.core import BearerJwtAuth, MusclesPackage, get_application_registry, inspect_application, install_package
from muscles.asgi import MuscularAsgiApp, RestApi, TestClient, asgi_app, mount_api
from muscles.permissions import (
    Permission, PermissionContext, PermissionDenied, PermissionEvaluator,
    PermissionRegistry, PermissionsPackage, Policy, PolicyExtension, PolicySource,
)


DELETE_DOCUMENT = Permission(
    "documents:delete", "Delete document",
    {"owner": Policy("Owner", lambda ctx: ctx.subject == ctx.resource)},
    ("owner",),
)


class DocumentsPackage(MusclesPackage):
    namespace = "documents"

    def permissions(self):
        return [DELETE_DOCUMENT]


def test_package_lifecycle_route_catalog_and_business_evaluation():
    class App:
        pass

    app = App()
    install_package(app, {}, PermissionsPackage())
    install_package(app, {}, DocumentsPackage())
    registry = app.container.resolve(PermissionRegistry)
    assert registry.get("documents:delete") is DELETE_DOCUMENT

    api = RestApi(prefix="/api", name="test")

    @api.init("/documents/{uid}", key="delete", method="DELETE", permission=DELETE_DOCUMENT)
    def delete(request, uid):
        return None

    mount_api(app, api)
    route = next(record for record in api.nodes_map if record["key"] == "delete")
    assert route["permission"] is DELETE_DOCUMENT
    projected = next(item for item in get_application_registry(app).routes if item.node.key == "delete")
    assert projected.permission == "documents:delete"
    inspected = next(item for item in inspect_application(app)["routes"] if item["name"] == "delete")
    assert inspected["permission"] == "documents:delete"
    evaluator = app.container.resolve(PermissionEvaluator)
    assert evaluator.require("documents:delete", PermissionContext("alice", "alice")).allowed
    with pytest.raises(PermissionDenied):
        evaluator.require(DELETE_DOCUMENT, PermissionContext("alice", "bob"))


def test_unknown_route_permission_fails_at_mount():
    class App:
        pass

    api = RestApi(prefix="/api", name="test-unknown")

    @api.init("/unknown", key="unknown", method="GET", permission="missing:read")
    def handler(request):
        return None

    with pytest.raises(ValueError, match="Unknown route permission"):
        mount_api(App(), api)


def test_http_authentication_and_permission_are_checked_before_handler():
    permission = Permission(
        "documents:generate", "Generate",
        {"allowed": Policy("Allowed", lambda ctx: getattr(ctx.subject, "uid", None) == "alice")},
        ("allowed",),
    )
    calls = []

    class Package(MusclesPackage):
        namespace = "documents"

        def permissions(self):
            return [permission]

    class App(MuscularAsgiApp):
        def __init__(self):
            self.api = RestApi(prefix="/permissions-test", name="permissions-http-test")
            self.auth = BearerJwtAuth(secret="test-secret")
            install_package(self, {}, PermissionsPackage())
            install_package(self, {}, Package())

            @self.api.init("/generate", key="generate", method="GET", auth=self.auth, permission=permission)
            def generate(request):
                calls.append(request.actor.uid)
                return {"ok": True}

    app = App()
    client = TestClient(asgi_app(app))
    assert client.get("/permissions-test/generate").status_code == 401
    assert client.with_bearer(app.auth.issue({"sub": "bob"})).get("/permissions-test/generate").status_code == 403
    assert client.with_bearer(app.auth.issue({"sub": "alice"})).get("/permissions-test/generate").status_code == 200
    assert calls == ["alice"]


def test_route_permission_fails_closed_without_evaluator_service():
    class App(MuscularAsgiApp):
        def __init__(self):
            self.api = RestApi(prefix="/permission-no-service", name="permissions-no-service-test")
            install_package(self, {}, DocumentsPackage())

            @self.api.init("/delete", key="delete", method="GET", permission=DELETE_DOCUMENT)
            def delete(request):
                return {"executed": True}

    response = TestClient(asgi_app(App())).get("/permission-no-service/delete")
    assert response.status_code == 403


def test_business_check_mode_uses_loaded_resource():
    permission = Permission(
        "documents:edit", "Edit document",
        {"owner": Policy("Owner", lambda ctx: ctx.resource is not None and ctx.subject == ctx.resource)},
        ("owner",),
    )

    class Package(MusclesPackage):
        namespace = "documents"

        def permissions(self):
            return [permission]

    class App(MuscularAsgiApp):
        def __init__(self):
            self.api = RestApi(prefix="/permission-business", name="permissions-business-test")
            install_package(self, {}, PermissionsPackage())
            install_package(self, {}, Package())

            @self.api.init("/edit", key="edit", method="GET", permission=permission, permission_check="business")
            def edit(request):
                evaluator = self.container.resolve(PermissionEvaluator)
                evaluator.require(permission, PermissionContext(subject="alice", resource="alice"))
                return {"ok": True}

    response = TestClient(asgi_app(App())).get("/permission-business/edit")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_policy_source_is_resolved_from_container_and_rechecked_each_time():
    class Source:
        selected = []

        def get_policies(self, permission, context):
            return self.selected

    class App:
        pass

    app = App()
    install_package(app, {}, PermissionsPackage())
    install_package(app, {}, DocumentsPackage())
    source = Source()
    app.container.register(PolicySource, source)
    evaluator = app.container.resolve(PermissionEvaluator)
    context = PermissionContext(subject="alice", resource="alice")
    assert not evaluator.evaluate(DELETE_DOCUMENT, context).allowed
    source.selected = ["owner"]
    assert evaluator.evaluate(DELETE_DOCUMENT, context).allowed


@pytest.mark.parametrize("extension_first", [True, False])
def test_external_package_adds_policy_independently_of_installation_order(extension_first):
    class EditorialPackage(MusclesPackage):
        namespace = "editorial"

        def permission_policies(self):
            return [PolicyExtension("documents:delete", "editor", Policy("Editor", lambda ctx: ctx.subject == "editor"))]

    class App:
        pass

    app = App()
    install_package(app, {}, PermissionsPackage())
    packages = [EditorialPackage(), DocumentsPackage()] if extension_first else [DocumentsPackage(), EditorialPackage()]
    for package in packages:
        install_package(app, {}, package)
    registry = app.container.resolve(PermissionRegistry)
    registry.validate()
    assert set(registry.get("documents:delete").get_policies()) == {"owner", "editor"}
    assert set(DELETE_DOCUMENT.get_policies()) == {"owner"}
    evaluator = app.container.resolve(PermissionEvaluator)
    assert evaluator.evaluate(DELETE_DOCUMENT, policies=["editor"], subject="editor").allowed
    assert not evaluator.evaluate(DELETE_DOCUMENT, subject="editor", resource="other").allowed
    other_app = App()
    install_package(other_app, {}, PermissionsPackage())
    install_package(other_app, {}, DocumentsPackage())
    assert set(other_app.container.resolve(PermissionRegistry).get("documents:delete").policies) == {"owner"}


def test_extension_collisions_and_missing_permission_are_rejected():
    class App:
        pass

    class Duplicate(MusclesPackage):
        namespace = "duplicate"

        def permission_policies(self):
            return [PolicyExtension("documents:delete", "owner", Policy("Owner", lambda ctx: True))]

    app = App()
    install_package(app, {}, DocumentsPackage())
    with pytest.raises(ValueError, match="Duplicate permission policy"):
        install_package(app, {}, Duplicate())

    app = App()
    install_package(app, {}, Duplicate())
    with pytest.raises(ValueError, match="Duplicate permission policies"):
        install_package(app, {}, DocumentsPackage())

    class Missing(MusclesPackage):
        namespace = "missing"

        def permission_policies(self):
            return [PolicyExtension("other:delete", "editor", Policy("Editor", lambda ctx: True))]

    app = App()
    install_package(app, {}, Missing())
    with pytest.raises(ValueError, match="Unknown permissions"):
        asgi_app(app)

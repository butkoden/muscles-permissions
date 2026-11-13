from __future__ import annotations

from muscles.core import MusclesPackage, PackageService, RoutePermissionChecker, get_application_registry

from .permissions import (PermissionContext, PermissionEvaluator, PermissionRegistry,
                          PermissionResourceRegistry, PolicySource)


class _PermissionRouteChecker(RoutePermissionChecker):
    def __init__(self, evaluator: PermissionEvaluator) -> None:
        self.evaluator = evaluator

    def check_route(self, request, permission) -> bool:
        services = getattr(request, "container", None)
        if not hasattr(services, "resolve"):
            services = self.evaluator.services
        context = PermissionContext(
            subject=getattr(request, "actor", None),
            attributes={"request": request},
            services=services,
        )
        return self.evaluator.evaluate(permission, context).allowed


class PermissionsPackage(MusclesPackage):
    """Install the shared application registry and evaluator into the container."""

    namespace = "permissions"

    def __init__(self, app=None, config=None, *, source: PolicySource | None = None) -> None:
        self.source = source

    def services(self, app, runtime):
        del runtime
        application_registry = get_application_registry(app)
        registry = PermissionRegistry(application_registry.permissions, application_registry.permission_policy_extensions)
        resource_registry = PermissionResourceRegistry()
        application_registry.subscribe_extensions("muscles.permissions.resources", resource_registry.register)

        def build_evaluator():
            source = self.source
            if source is None:
                try:
                    source = app.container.resolve(PolicySource)
                except KeyError:
                    pass
            return PermissionEvaluator(registry, source, services=app.container)

        return [
            PackageService(PermissionRegistry, registry),
            PackageService(PermissionResourceRegistry, resource_registry),
            PackageService(PermissionEvaluator, build_evaluator),
            PackageService(RoutePermissionChecker, lambda: _PermissionRouteChecker(
                app.container.resolve(PermissionEvaluator)
            )),
        ]

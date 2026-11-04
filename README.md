# muscles-permissions

App-scoped permission declarations and policy evaluation for Muscles. Install
`muscles-permissions` and import `muscles.permissions`. This version requires
the corresponding Muscles core changes in this workspace, including the
`permissions()` package hook and `RoutePermissionChecker`.

```python
from muscles import MusclesPackage, install_package
from muscles.permissions import Permission, PermissionContext, Policy, PermissionsPackage

def handle_owner_policy(context: PermissionContext) -> bool:
    return context.resource is not None and context.subject.uid == context.resource.author_uid

DELETE_DOCUMENT = Permission(
    id="documents:delete",
    title="Delete document",
    policies={"owner": Policy(title="Owner", handler=handle_owner_policy)},
    default_policies=("owner",),
)

class DocumentsPackage(MusclesPackage):
    namespace = "documents"

    def permissions(self):
        return [DELETE_DOCUMENT]

install_package(app, {}, PermissionsPackage())
install_package(app, {}, DocumentsPackage())
```

Package declarations are collected in the application registry. Duplicate IDs
fail installation. Resolve `PermissionRegistry` and `PermissionEvaluator` from
`app.container` to list declarations and evaluate them in business logic.

Another package can contribute handlers without importing the owner package:

```python
from muscles import MusclesPackage
from muscles.permissions import Policy, PolicyExtension

class EditorialPackage(MusclesPackage):
    namespace = "editorial"

    def permission_policies(self):
        return [PolicyExtension(
            permission_id="documents:delete",
            policy_id="editor",
            policy=Policy("Editor", handle_editor_policy),
        )]
```

Extensions may be installed before or after their target package. Duplicate
policy IDs are rejected, and ASGI mounting rejects extensions whose permission
was never registered. For applications without ASGI mounting, call
`PermissionRegistry.validate()` after installing packages. The merged policies
are available through `registry.get("documents:delete").get_policies()`;
the original declaration is immutable and shared safely between applications.
Extensions do not change defaults and only run when selected by trusted code or
an assignment source. For an existing permission, `registry.register_policy`
also supports direct registration.

```python
from muscles.permissions import PermissionEvaluator, PermissionContext

evaluator = app.container.resolve(PermissionEvaluator)
decision = evaluator.evaluate(
    permission=DELETE_DOCUMENT,
    policies=["owner"],
    subject=user,
    resource=document,
)
```

`require` raises `PermissionDenied` when denied; the calling transport must map
that exception to its own response. `evaluate` returns a `Decision`. Selected
policies use OR semantics. An absent assignment (`None`) uses the declared
defaults; an explicit empty sequence denies access. Unknown IDs fail. Handlers
must return the boolean `True` to allow the action.

Policy IDs identify handlers; a handler may check an ownership relation, role,
or another privilege. Handlers run in the order requested and evaluation stops
at the first `True`. Handler errors propagate and do not grant permission.
Handlers may call `context.resolve(ServiceInterface)` to obtain a service
registered in the application container, without importing its implementation.
For route checks a request-scoped resolver is used when available. Explicit
`policies` can narrow the configured `PolicySource` assignment but cannot grant
checks that the source did not assign. Never treat a caller-supplied list as an
assignment.

An optional `PolicySource` service supplies assignments. Register it in the
application container before the evaluator is first resolved. Its
`get_policies(permission, context)` returns policy IDs or `None` for defaults.
It is consulted for each evaluation; persistence is supplied by the application.
When code passes an explicit policy list, the evaluator intersects it with the
assigned list. Business code can narrow the checks used for an operation, but
cannot bypass the subject's assigned policies.

For ASGI `RestApi`, `@api.init(..., permission=DELETE_DOCUMENT)` associates a
route with a registered declaration. Mounting fails for an unknown ID. After
authentication and middleware, the framework checks the permission before the
handler, using `request.actor` as subject and the request in
`context.attributes["request"]`. A missing checker denies the request. This
route check has no loaded resource.

When a policy needs a loaded object, explicitly use
`permission_check="business"` on the route and call `evaluator.require(...)`
in the shared business operation after loading it. In this mode the route check
is skipped; every caller must use the protected business operation. The library
does not authenticate users or implement role assignments itself.
Repository: https://github.com/butkoden/muscles-permissions

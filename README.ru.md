# muscles-permissions

Библиотека объявляет права и проверяет политики в контексте приложения Muscles.
Дистрибутив называется `muscles-permissions`, импорт — `muscles.permissions`.
Нужна версия ядра Muscles с изменениями этого проекта: хуком пакета
`permissions()` и интерфейсом `RoutePermissionChecker`.

Пакет приложения возвращает декларации `Permission` из своего метода
`permissions()`. При `install_package` они собираются в общий реестр;
повторный ID вызывает ошибку. Установите `PermissionsPackage` через тот же
`install_package` и получите `PermissionRegistry` или `PermissionEvaluator`
из `app.container`.

Сторонний пакет может добавить обработчик к праву, не импортируя пакет-владелец:

```python
from muscles import MusclesPackage
from muscles.permissions import Policy, PolicyExtension

class EditorialPackage(MusclesPackage):
    namespace = "editorial"

    def permission_policies(self):
        return [PolicyExtension(
            permission_id="documents:delete",
            policy_id="editor",
            policy=Policy("Редактор", handle_editor_policy),
        )]
```

Расширение можно устанавливать до или после пакета-владельца. Повторный ID
политики отклоняется; при монтировании ASGI обнаруживается несуществующее право.
Приложение без ASGI вызывает `PermissionRegistry.validate()` после установки
пакетов. Полный набор доступен через
`registry.get("documents:delete").get_policies()`: исходная декларация не
изменяется, поэтому расширения разных приложений не смешиваются. Дополнительные
обработчики не меняют настройки по умолчанию и вызываются только при выборе
доверенным кодом или источником назначений. Для уже зарегистрированного права
доступен также прямой вызов `registry.register_policy(...)`.

`Permission` содержит ID, название, доступные `Policy` и `default_policies`.
Обработчик политики получает `PermissionContext` с пользователем, ресурсом и
дополнительными данными и должен вернуть именно `True` для разрешения.
Политики из списка объединяются через «ИЛИ». Отсутствие назначения (`None`)
использует настройки по умолчанию; пустой список запрещает доступ.

ID политики обозначает обработчик проверки привилегий: тот может проверять
владельца, роль или другое условие. Обработчики выполняются в указанном порядке
до первого `True`; исключение обработчика передаётся вызывающему коду. Для
получения сервиса другого пакета обработчик вызывает
`context.resolve(ИнтерфейсСервиса)`; реализация берётся из контейнера приложения
или контекста запроса. Явный список `policies` обходит `PolicySource`, поэтому
его должен выбирать доверенный код приложения, а не пользователь в запросе.

```python
decision = evaluator.evaluate(
    permission=UPDATE_DOCUMENT,
    policies=["owner", "editor"],
    subject=current_user,
    resource=document,
)
```

`PolicySource` — необязательный интерфейс источника назначений. Зарегистрируйте
его в контейнере до первого получения evaluator. Его метод `get_policies`
вызывается при каждой проверке и возвращает список ID либо `None`. Хранение
ролей и назначений реализует приложение.

`@api.init(..., permission=ПРАВО)` связывает маршрут `RestApi` с декларацией;
неизвестный ID вызывает ошибку монтирования. После аутентификации и middleware
перед обработчиком выполняется проверка с `request.actor`. Без сервиса проверки
доступ запрещён. Если политика зависит от загруженного объекта, укажите
`permission_check="business"` и вызовите `PermissionEvaluator.require()` в
общей бизнес-операции после загрузки объекта. При этом автоматическая проверка
маршрута отключается, и все вызовы должны проходить через эту операцию.

`require` вызывает `PermissionDenied` при отказе; транспорт бизнес-операции
должен преобразовать исключение в свой ответ. Пакет не выполняет JWT-
аутентификацию и не назначает роли. Пример кода доступен в `README.md`.
Репозиторий: https://github.com/butkoden/muscles-permissions

## Обработчик прав для сущности из другого пакета

Допустим, файл прикреплён к записи `records:record`. При чтении файла пакету
`storage` нужно проверить доступ к записи. Чтобы `storage` не импортировал
`records`, пакет `records` объявляет обработчик через расширение Muscles, а
`muscles-permissions` сохраняет его в `PermissionResourceRegistry`.

Обработчик содержит:

- `resource_type` — тип сущности, по которому его можно найти;
- `permissions` — соответствие действия идентификатору разрешения;
- `resolver` — функцию, которая загружает сущность для проверки.

Ниже полный пример для одного приложения. Словарь `records` заменяет
репозиторий; в настоящем пакете resolver должен загружать сущность с учётом
контекста запроса и ограничений доступа к данным.

```python
from types import SimpleNamespace

from muscles import MusclesPackage, PackageExtension, install_package
from muscles.permissions import (
    Permission,
    PermissionContext,
    PermissionEvaluator,
    PermissionRegistry,
    PermissionResourceHandler,
    PermissionResourceRegistry,
    PermissionsPackage,
    Policy,
)


records = {
    "record-1": {"uid": "record-1", "owner_uid": "user-1"},
}


def is_owner(context):
    return (
        context.subject is not None
        and context.resource is not None
        and context.subject.uid == context.resource["owner_uid"]
    )


RECORD_READ = Permission(
    id="records:records.read",
    title="Чтение записи",
    policies={"owner": Policy("Владелец", is_owner)},
    default_policies=("owner",),
)


def resolve_record(uid, context):
    # В приложении используйте репозиторий и context.attributes["request"].
    return records.get(uid)


class RecordsPackage(MusclesPackage):
    namespace = "records"

    def permissions(self):
        return [RECORD_READ]

    def extensions(self):
        return [PackageExtension(
            target="muscles.permissions.resources",
            value=PermissionResourceHandler(
                resource_type="records:record",
                permissions={"read": "records:records.read"},
                resolver=resolve_record,
            ),
        )]


# app — заранее созданное приложение Muscles.
# Порядок установки можно поменять: расширение будет доставлено в обоих случаях.
install_package(app, {}, RecordsPackage())
install_package(app, {}, PermissionsPackage())

permissions = app.container.resolve(PermissionRegistry)
resources = app.container.resolve(PermissionResourceRegistry)
evaluator = app.container.resolve(PermissionEvaluator)

# Выполните после установки всех пакетов.
resources.validate(permissions)

# Например, storage получил эти значения из своей записи о файле.
resource_type = "records:record"
resource_uid = "record-1"
action = "read"
user = SimpleNamespace(uid="user-1")

handler = resources.get(resource_type)
if handler is None or action not in handler.permissions:
    allowed = False
else:
    base_context = PermissionContext(
        subject=user,
        attributes={"operation": action},
        services=app.container,
    )
    resource = handler.resolver(resource_uid, base_context)
    if resource is None:
        allowed = False
    else:
        context = PermissionContext(
            subject=user,
            resource=resource,
            attributes=base_context.attributes,
            services=app.container,
        )
        allowed = evaluator.evaluate(handler.permissions[action], context).allowed

assert allowed is True
```

Если обработчик не найден, действие не объявлено, сущность не загружена или
политика отказала — файл показывать нельзя. `PermissionResourceRegistry`
отклоняет повторную регистрацию одного `resource_type`. Его `validate()`
проверяет существование всех указанных permission ID; вызывайте проверку после
установки пакетов. Порядок установки не влияет на доставку расширения: Muscles
сохраняет объявление до подписки и передаёт новые объявления подписчику сразу.

Сам реестр расширений хранится в памяти приложения; связь файла с сущностью
должна сохраняться отдельно, например в базе данных пакета `storage`.

import pytest

from django_action_permissions.mixins import CodeInfoPermissionMixin, OperationInfoPermissionMixin


def test_operation_mixin_returns_its_operation():
    class Mixin(OperationInfoPermissionMixin):
        _operation = "approve"

    assert Mixin().get_operation(request=None, view=None) == "approve"


def test_operation_mixin_without_operation_is_a_mistake():
    with pytest.raises(AssertionError, match="without operation"):
        OperationInfoPermissionMixin().get_operation(request=None, view=None)


def test_code_mixin_returns_its_permission_code():
    class Mixin(CodeInfoPermissionMixin):
        _perm_code = "shop.view_order"

    assert Mixin().get_perm_code() == "shop.view_order"


def test_code_mixin_without_code_is_a_mistake():
    with pytest.raises(AssertionError, match="without perm_code"):
        CodeInfoPermissionMixin().get_perm_code()

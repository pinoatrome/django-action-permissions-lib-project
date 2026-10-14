class OperationInfoPermissionMixin:
    """Can be used with BaseActionModelPermission for a specific action"""
    _operation = None

    def get_operation(self, request, view, instance=None):
        assert self._operation, f'OperationInfoPermissionMixin {self} without operation'
        return self._operation


class CodeInfoPermissionMixin:
    """Can be used with BaseActionModelPermission for a specific perm_code"""
    _perm_code = None

    def get_perm_code(self, *args, **kwargs):
        assert self._perm_code, f'CodeInfoPermissionMixin {self} without perm_code'
        return self._perm_code

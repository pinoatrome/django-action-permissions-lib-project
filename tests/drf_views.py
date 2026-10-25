"""DRF viewsets over the users, for the tests that go through HTTP (only when DRF is installed)."""

from django.contrib.auth import get_user_model
from rest_framework import routers, serializers, viewsets
from rest_framework.permissions import DjangoObjectPermissions

from django_action_permissions.permissions import BaseActionModelPermission


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ["id", "username"]


class UserViewSet(viewsets.ModelViewSet):
    queryset = get_user_model().objects.order_by("pk")
    serializer_class = UserSerializer
    permission_classes = [BaseActionModelPermission]


router = routers.SimpleRouter()
router.register("users", UserViewSet, basename="user")


class ObjectPermissions(DjangoObjectPermissions):
    """DRF's own object permissions, reading (GET) asking for view_<model> too."""

    perms_map = {**DjangoObjectPermissions.perms_map, "GET": ["%(app_label)s.view_%(model_name)s"]}


class ObjectPermissionsUserViewSet(UserViewSet):
    permission_classes = [ObjectPermissions]


router.register("object-users", ObjectPermissionsUserViewSet, basename="object-user")

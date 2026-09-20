from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .housekeeping import HousekeepingError, status, dry_run, purge, save_config
from .views import _require_module_manager

class HousekeepingStatusView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self,request):
        _require_module_manager(request.user)
        try:return Response(status())
        except HousekeepingError as exc:return Response({'detail':str(exc)},status=500)
    def put(self,request):
        _require_module_manager(request.user)
        try:return Response(save_config(request.data))
        except (HousekeepingError,ValueError,TypeError) as exc:return Response({'detail':str(exc)},status=400)

class HousekeepingPurgeView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self,request):
        _require_module_manager(request.user)
        cats=request.data.get('categories') or None; simulate=bool(request.data.get('dry_run',False))
        try:return Response(dry_run(cats) if simulate else purge(cats))
        except HousekeepingError as exc:return Response({'detail':str(exc)},status=400)

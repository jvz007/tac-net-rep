from rest_framework.response import Response
from rest_framework.views import APIView
from tec_tac_packagetest.sample import sample_device
from tec_tac_packagetest.permissions import PackageTestPermission
from tec_tac_packagetest_reportset.sample import map_device

class PackageTestView(APIView):
    permission_classes=[PackageTestPermission]
    def get(self,request): return Response(map_device(sample_device()))
    def post(self,request):
        payload={"device":request.data.get("device","posted-device"),"status":request.data.get("status","up"),"latency_ms":request.data.get("latency_ms",0)}
        return Response(map_device(payload),status=201)

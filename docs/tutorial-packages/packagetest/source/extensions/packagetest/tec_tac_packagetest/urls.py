from django.urls import path
from tec_tac_packagetest.views import PackageTestView
app_name="tec_tac_packagetest"
urlpatterns=[path("sample/",PackageTestView.as_view(),name="sample")]

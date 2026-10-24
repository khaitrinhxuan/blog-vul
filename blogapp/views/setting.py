from django.views.generic import ListView
from blogapp.models.Setting import Vul
from django.shortcuts import render
import jwt
from decouple import config
from django.template import engines
from core.lib import jwt_vul


class settingView(ListView):
    template_name = "setting.html"
    nameVuls = Vul.objects.values("name")

    def get(self, request):
        object_list = Vul.objects.all()
        ssti = Vul.objects.filter(name="SSTI").values()[0]["status"]
        if ssti:
            engine = engines["django"]
            request.user.username = engine.from_string(request.user.username).render()
            object_list = Vul.objects.all()
            return render(request, self.template_name, {"object_list": object_list})
        else:
            return render(request, self.template_name, {"object_list": object_list})

    def post(self, request):
        object_list = Vul.objects.all()
        jwt_confusion = Vul.objects.filter(name="JWT_Key_Confusion").values()[0]["status"]
        jwts = Vul.objects.filter(name="JWT").values()[0]["status"]
        if request.user.username:
            cookie_check = request.COOKIES["auth"]
            try:
                if jwt_confusion and not jwts:
                    with open(config("PUBLICKEY"), "r") as keyfile:
                        publickey = keyfile.read()
                    cookie_decode = jwt.decode(cookie_check, publickey, algorithms=["RS256"])

                elif jwts:
                    key = request.session["key"]
                    cookie_decode = jwt_vul.decode(cookie_check, key)

                else:

                    key = request.session["key"]
                    cookie_decode = jwt.decode(cookie_check, key, algorithms=["HS256"])

            except Exception:
                cookie_decode = None

            if cookie_decode and cookie_decode["admin"]:

                for _vuls in self.nameVuls:

                    if request.POST[_vuls["name"]] == "yes":
                        Vul.objects.filter(name=_vuls["name"]).update(status=True)
                    else:
                        Vul.objects.filter(name=_vuls["name"]).update(status=False)

                return render(request, self.template_name, {"object_list": object_list, "msg": "Change is success!"})
            else:

                return render(
                    request, self.template_name, {"object_list": object_list, "msg": "You don't have permission"}
                )

        else:
            return render(
                request, self.template_name, {"object_list": object_list, "msg": "Please login to apply this change!"}
            )

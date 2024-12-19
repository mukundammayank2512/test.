# backend/files/views.py
from rest_framework.views import APIView
# from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from .models import File, CustomUser, ShareableLink
from django.http import FileResponse, JsonResponse
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login
from .utils import generate_otp, send_otp_sms, role_required, require_https
import os
import base64
from .serializers import CustomUserSerializer
from django.core.serializers import serialize
from django.utils.timezone import now, timedelta
from django.utils.decorators import method_decorator
from django.http import HttpResponse
# from django.views.decorators.http import require_https


# @method_decorator(role_required(allowed_roles=['admin', 'user']), name='dispatch')
class FileUploadView(APIView):

    def post(self, request):
        # user = request.user 
        # if not user.is_loggedin:
        #     return JsonResponse({"error":"Please login to continue"}, status = 400)
        uploaded_file = request.FILES.get('file')
        # uploaded_file = request.get('file')
        print(uploaded_file)
        if not uploaded_file:
            return Response({"error": "No file uploaded"}, status=400)

        new_file = File.objects.create(file=uploaded_file)
        new_file.encrypt(new_file.file.path)

        return Response({
            "message": "File uploaded and encrypted successfully!",
            "file_id": new_file.id
        }, status=201)

# @method_decorator(role_required(allowed_roles=['admin','user','guest']), name='dispatch')
class FileDecryptView(APIView):
    def get(self, request, file_id):
        # user = request.user 
        # if not user.is_loggedin:
        #     return JsonResponse({"error":"Please login to continue"}, status = 400)
        try:
            file_obj = File.objects.get(id=file_id)

            decrypted_data = file_obj.decrypt(file_obj.file.path)

            temp_path = f"{file_obj.file.path}.decrypted"
            with open(temp_path, 'wb') as temp_file:
                temp_file.write(decrypted_data)
 
            response = FileResponse(open(temp_path, 'rb'), as_attachment=True, filename=os.path.basename(file_obj.file.name))
            
            

            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_obj.file.name)}"'
            os.remove(temp_path)

            return response

        except File.DoesNotExist:
            return Response({"error": "File not found"}, status=404)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

# @method_decorator(role_required(allowed_roles=['admin', 'user']), name='dispatch')
class ShareFileView(APIView):
    # permission_classes = [IsAuthenticated]
    def post(self, request, file_id):
        # user = request.user
        # if not user.is_loggedin:
        #     return JsonResponse({"error":"Please login to continue"}, status = 400)
        try:
            file = File.objects.get(id = file_id)

            # print(file)
            expires_at = now() + timedelta(minutes = (request.data.get('exp_time', 60)))
            shareable_link = ShareableLink.objects.create(file = file, expires_at = expires_at)
            return Response({"shareable_link":f"/shared/{shareable_link.token}"})
        except File.DoesNotExist:
            return Response({"error": "File not found or unauthorized."}, status=404)

# @method_decorator(require_https, name='dispatch')
class RegisterView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully!"}, status=201)
        return Response({"errors": serializer.errors}, status=400)
        

class LoginWithOTPView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        
        user = authenticate(username=username, password=password)
        # print(user.id)
        # user.is_loggedin = True
        if user:
            # otp = generate_otp()

            # send_otp_sms(user.phone, otp)

            # request.session['otp'] = otp
            request.session['user_id'] = user.id
            print(request.session.items())
            # request.session.save()

            return JsonResponse({"message": "OTP sent to your registered phone number."}, status=200)
        else:
            return JsonResponse({"error": "Invalid username or password."}, status=400)

class Logout(APIView):
    def post(self, request):
        if request.user.is_loggedin:
            request.user.is_loggedin = False
            return JsonResponse({"message": "Log out successful"}, status = 200)
        return JsonResponse({"error":"Please login to continue"})

class VerifyOTPView(APIView):
    def post(self, request):
        # otp = request.data.get("otp")
        # session_otp = request.session.get('otp')
        user_id = request.session.get('user_id')
        # print(user_id)

        if not user_id:
            return JsonResponse({"error": "Session expired or OTP not sent."}, status=400)

        # if otp==session_otp:
        if True:
            user = request.user
            user.is_loggedin = True
            login(request, user)

            del request.session['otp']
            del request.session['user_id']

            return JsonResponse({"message": "Login successful!"}, status=200)
        else:
            return JsonResponse({"error": "Invalid OTP."}, status=400)

# @method_decorator(role_required(allowed_roles=['admin']), name='dispatch')
class AdminManageView(APIView):

    def get(self, request):
        # user = request.user
        # if not user.is_loggedin:
        #     return JsonResponse({"error":"Please login to continue"}, status = 400)
        files = File.objects.all()
        users = CustomUser.objects.all()

        file_json_data = serialize('json', files)
        user_json_data = serialize('json', users)



        return JsonResponse({"files":file_json_data, "users":user_json_data}, status = 200)

# @method_decorator(role_required(allowed_roles=['admin','user','guest']), name='dispatch')
class ViewSharedFile(APIView):
    def get(self, request):
        # user = request.user
        # if not user.is_loggedin:
        #     return JsonResponse({"error":"Please login to continue"}, status = 400)
        if request.GET.get('token'):
            token = request.GET.get('token')
            link = ShareableLink.objects.get(token = token)
            if not link.is_valid():
                return JsonResponse({"error":"Link Expired"}, status = 200)
            
            file = link.file

            decrypted_data = file.decrypt(file.file.path)
            print(decrypted_data)
            base64_data = base64.b64encode(decrypted_data).decode('utf-8')

            
            return JsonResponse({"data":base64_data}, status = 200)
        else:
            files = File.objects.get(shared_with = request.user)
            file_json_data = serialize('json', files)
            return JsonResponse({"files": file_json_data}, status = 200)
        
        
    






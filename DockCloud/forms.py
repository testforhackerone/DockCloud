from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import CustomUser
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from PIL import Image
import magic, io, hashlib, os


class ProfileImageForm(UserChangeForm):
    image = forms.ImageField(required=False, widget=forms.FileInput)

    class Meta:
        model = CustomUser
        fields = ('image',)

    def clean_image(self):
        image = self.cleaned_data.get('image')
        print(image.size)
        if image.size > 1 * 1024 * 1024 or image.size < 50 * 1024:
            raise ValidationError('The maximum file size is 1MB, minimum file size in 50KB.')
        mime_type = magic.from_buffer(image.read(1024), mime=True)
        if mime_type == 'image/png':
            image_format = 'PNG'
        elif mime_type == 'image/jpeg':
            image_format = 'JPEG'
        else:
            raise ValidationError('Invalid file type. Please upload a PNG or JPEG image.')
        with Image.open(image) as img:
            # resize the image to make it more smaller
            img.thumbnail((640, 640))
            buffer = io.BytesIO()
            img.save(buffer, format=image_format)
            image_file = buffer.getvalue()
            # rename the image
            filename, ext = os.path.splitext(image.name)
            return ContentFile(image_file, name=str(self.instance.id) + ext)


class UserCreationForm(UserCreationForm):

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'address', 'security_q1', 'security_q2', 'security_q3']

class UserProfileForm(forms.ModelForm):

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'address']


class SecurityQuestionsForm(forms.ModelForm):

    class Meta:
        model = CustomUser
        fields = ['username', 'security_q1', 'security_q2', 'security_q3']

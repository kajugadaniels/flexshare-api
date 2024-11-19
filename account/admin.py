from django.contrib import admin
from django.utils.html import format_html
from account.models import *

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'phone_number', 'status', 'role', 'country', 'is_active', 'user_image')
    list_filter = ('status', 'role', 'gender', 'country', 'is_active')
    search_fields = ('name', 'email', 'phone_number')
    readonly_fields = ('created_at', 'user_image_display')

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('name', 'phone_number', 'national_id', 'gender', 'date_of_birth', 'bio')}),
        ('Location', {'fields': ('country', 'district', 'sector', 'cell', 'village')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'status', 'role')}),
        ('Important dates', {'fields': ('created_at',)}),
        ('Profile Picture', {'fields': ('user_image_display',)}),
    )

    def user_image_display(self, obj):
        if obj.image:
            return format_html('<img src="{}" style="width: 45px; height:45px;" />', obj.image.url)
        return "No image"
    user_image_display.short_description = "Current Image"

    def user_image(self, obj):
        return format_html('<img src="{}" style="width: 45px; height:45px;" />', obj.image.url) if obj.image else "None"
    user_image.short_description = 'Profile Image'

    def get_form(self, request, obj=None, **kwargs):
        form = super(UserAdmin, self).get_form(request, obj, **kwargs)
        form.base_fields['password'].widget.attrs['autocomplete'] = 'new-password'  # Ensures password fields do not autocomplete
        return form
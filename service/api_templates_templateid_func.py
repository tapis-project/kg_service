from fastapi import APIRouter
from models_misc import SetPermission
from models_templates import Template, TemplatePermissionsResponse
from models_templates_tags import TemplateTagsResponse, TemplateTagResponse, NewTemplateTag, TemplateTag
from tapisservice.tapisfastapi.utils import g, ok, error
from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)

router = APIRouter()


### Permissions
@router.get(
    "/pods/templates/{template_id}/permissions",
    tags=["Templates"],
    summary="get_template_permissions",
    operation_id="get_template_permissions",
    response_model=TemplatePermissionsResponse)
async def get_template_permissions(template_id):
    """
    Get a templates permissions.

    Note:
    - There are 3 levels of permissions, READ, USER, and ADMIN.
    - Permissions are granted/revoked to individual TACC usernames.
    - Permissions can be set for TENANT or SITE keys for tenant-level or site-level sharing.

    Returns all template permissions.
    """
    logger.info(f"GET /pods/templates/{template_id}/permissions - Top of get_template_permissions.")

    template = Template.db_get_with_pk(template_id, tenant=g.request_tenant_id, site=g.site_id)

    return ok(result={"permissions": template.permissions}, msg = "Template permissions retrieved successfully.")


@router.post(
    "/pods/templates/{template_id}/permissions",
    tags=["Templates"],
    summary="set_template_permission",
    operation_id="set_template_permission",
    response_model=TemplatePermissionsResponse)
async def set_template_permission(template_id, set_permission: SetPermission):
    """
    Set a permission for a template.

    Returns updated template permissions.
    """
    logger.info(f"POST /pods/templates/{template_id}/permissions - Top of set_template_permission.")

    inp_user = set_permission.user
    inp_level = set_permission.level

    template = Template.db_get_with_pk(template_id, tenant=g.request_tenant_id, site=g.site_id)

    # Get formatted perms
    curr_perms = template.get_permissions()

    # Update variable
    curr_perms[inp_user] = inp_level

    # Ensure there's still one ADMIN role before finishing.
    if "ADMIN" not in curr_perms.values():
        raise KeyError(f"Operation would result in pod with no users in ADMIN role. Rolling back.")

    # Convert back to db format
    perm_list = []
    for user, level in curr_perms.items():
        perm_list.append(f"{user}:{level}")

    # Update pod object and commit
    template.permissions = perm_list
    template.db_update(f"'{g.username}' set permission for '{inp_user}' to {inp_level}")

    return ok(result={"permissions": template.permissions}, msg = "Template permissions updated successfully.")


@router.delete(
    "/pods/templates/{template_id}/permissions/{user}",
    tags=["Templates"],
    summary="delete_template_permission",
    operation_id="delete_template_permission",
    response_model=TemplatePermissionsResponse)
async def delete_template_permission(template_id, user):
    """
    Delete a permission from a template.

    Returns updated template permissions.
    """
    logger.info(f"DELETE /pods/{template_id}/permissions/{user} - Top of delete_template_permission.")

    template = Template.db_get_with_pk(template_id, tenant=g.request_tenant_id, site=g.site_id)

    # Get formatted perms
    curr_perms = template.get_permissions()

    if user not in curr_perms.keys():
        raise KeyError(f"Could not find permission for template with username {user} when deleting permission")

    # Delete permission
    del curr_perms[user]

    # Ensure there's still one ADMIN role before finishing.
    if "ADMIN" not in curr_perms.values():
        raise KeyError(f"Operation would result in template with no users in ADMIN role. Rolling back.")

    # Convert back to db format
    perm_list = []
    for user, level in curr_perms.items():
        perm_list.append(f"{user}:{level}")
    
    # Update template object and commit
    template.permissions = perm_list
    template.db_update(f"'{g.username}' deleted permission for '{user}'")

    return ok(result={"permissions": template.permissions}, msg = "Template permission deleted successfully.")
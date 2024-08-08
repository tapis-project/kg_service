from fastapi import APIRouter
from models_misc import SetPermission
from models_templates import Template, TemplatePermissionsResponse
from models_templates_tags import TemplateTagsResponse, TemplateTagResponse, NewTemplateTag, TemplateTag, TemplateTagsSmallResponse
from tapisservice.tapisfastapi.utils import g, ok, error
from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)

router = APIRouter()


#### Template Tags
@router.get(
    "/pods/templates/{template_id}/tags",
    tags=["Templates", "Tags"],
    summary="list_template_tags",
    operation_id="list_template_tags",
    response_model=TemplateTagsSmallResponse)
async def list_template_tags(template_id):
    """
    List tag entries the template has

    Returns the ledger of template tags
    """
    logger.info(f"GET /pods/templates/{template_id}/tags - Top of list_template_tags.")
    template_tags = TemplateTag.db_get_where(where_params=[['template_id', '.eq', template_id]], sort_column='creation_ts', tenant=g.request_tenant_id, site=g.site_id)

    display_template_tags = []
    for template_tag in template_tags:
        display_template_tags.append(template_tag.display_small())

    return ok(result=display_template_tags, msg = "Template tags retrieved successfully.")


@router.post(
    "/pods/templates/{template_id}/tags",
    tags=["Templates", "Tags"],
    summary="add_template_tag",
    operation_id="add_template_tag",
    response_model=TemplateTagResponse)
async def add_template_tag(template_id, new_template_tag: NewTemplateTag):
    logger.info(f"POST /pods/templates/{template_id}/tags - Top of add_template.")
    template_tag = TemplateTag(template_id=template_id, **new_template_tag.dict())

    # Create template database entry
    template_tag.db_create(tenant=g.request_tenant_id, site=g.site_id)
    logger.debug(f"New template_tag saved in db. template_id: {template_tag.template_id}; tenant: {g.request_tenant_id}.")

    return ok(result=template_tag.display(), msg="Template added successfully.")


@router.get(
    "/pods/templates/{template_id}/tags/{tag_id}",
    tags=["Templates", "Tags"],
    summary="get_template_tags",
    operation_id="get_template_tags",
    response_model=TemplateTagsResponse)
async def get_template_tags(template_id, tag_id):
    """
    List tag entries the template has

    Returns the ledger of template tags
    """
    logger.info(f"GET /pods/templates/{template_id}/tags/{tag_id} - Top of get_template_tag.")
    where_params = [['template_id', '.eq', template_id]]
    if "@" in tag_id: ### You could use just periods too if you need an alternative #or "." in tag_id:
        where_params.append(['tag_timestamp', '.eq', tag_id])
    else:
        where_params.append(['tag', '.eq', tag_id])
    template_tags = TemplateTag.db_get_where(where_params=where_params, sort_column="creation_ts", tenant=g.request_tenant_id, site=g.site_id)

    display_template_tags = []
    for template_tag in template_tags:
        display_template_tags.append(template_tag.display())

    return ok(result=display_template_tags, msg = "Template tags retrieved and filtered successfully.")

from fastapi import APIRouter
from models_templates import Template, TemplatesResponse, TemplateResponse, NewTemplate
from channels import CommandChannel
from tapisservice.tapisfastapi.utils import g, ok

from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)


router = APIRouter()


#### /pods/templates

@router.get(
    "/pods/templates",
    tags=["Templates"],
    summary="get_templates",
    operation_id="get_templates",
    response_model=TemplatesResponse)
async def get_templates():
    """
    Get all templates allowed globally + in respective tenant + for specific user.
    Returns a list of templates.
    """
    logger.info("GET /pods/templates - Top of get_templates.")

    # TODO search
    templates =  Template.db_get_all_with_permission(user=g.username, level='READ', tenant=g.request_tenant_id, site=g.site_id)

    templates_to_show = []
    for template in templates:
        templates_to_show.append(template.display())

    logger.info("Templates retrieved.")
    return ok(result=templates_to_show, msg="Templates retrieved successfully.")


@router.post(
    "/pods/templates",
    tags=["Templates"],
    summary="add_template",
    operation_id="add_template",
    response_model=TemplateResponse)
async def add_template(new_template: Template):
    """
    Add a template with inputted information.
    
    Returns new template object.
    """
    logger.info("POST /pods/templates - Top of add_template.")
    
    ### Validate input
    template = Template(**new_template.dict())

    # Create template database entry
    template.db_create()
    logger.debug(f"New template saved in db. template_id: {template.template_id}; tenant: {g.request_tenant_id}.")

    return ok(result=template.display(), msg="Template added successfully.")

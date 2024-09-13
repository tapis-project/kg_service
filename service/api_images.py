from fastapi import APIRouter
from models_images import Image, ImagesResponse, ImageResponse, NewImage
from channels import CommandChannel
from tapisservice.tapisfastapi.utils import g, ok
from codes import PermissionLevel
from tapisservice.config import conf
from tapisservice.logs import get_logger
logger = get_logger(__name__)


router = APIRouter()


#### /pods/images

@router.get(
    "/pods/images",
    tags=["Images"],
    summary="get_images",
    operation_id="get_images",
    response_model=ImagesResponse)
async def get_images():
    """
    Get all images allowed globally + in respective tenant.
    Returns a list of images.
    """
    logger.info("GET /pods/images - Top of get_images.")

    # TODO search
    images =  Image.db_get_all(tenant="siteadmintable", site=g.site_id)
#    images =  Image.db_get_all_with_permission(user=g.username, level='READ', tenant=g.request_tenant_id, site=g.site_id)

    images_to_show = []
    for image in images:
        images_to_show.append(image.display())

    logger.info("Images retrieved.")
    return ok(result=images_to_show, msg="Images retrieved successfully.")


@router.post(
    "/pods/images",
    tags=["Images"],
    summary="add_image",
    operation_id="add_image",
    response_model=ImageResponse)
async def add_image(new_image: NewImage):
    """
    Add a image with inputted information.
    
    Returns new image object.
    """
    logger.info("POST /pods/images - Top of add_image.")

    # Create image object. Validates as well.
    image = Image(**new_image.dict())

    pre_new_image = new_image.image
    post_new_image = image.image
    if pre_new_image != post_new_image and ":" in pre_new_image:
        metadata = {"notice": "removed tag from image, tag enforcement does not yet exist"}

    # Create image database entry
    image.db_create(tenant="siteadmintable", site=g.site_id)
    logger.debug(f"New image saved in db. image: {image.display()}.")

    return ok(result=image.display(), msg="Images added successfully.", metadata=metadata)

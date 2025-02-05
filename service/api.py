from utils import error_handler, HttpUrlRedirectMiddleware
from tapisservice.tapisfastapi.utils import GlobalsMiddleware
from tapisservice.tapisfastapi.auth import TapisMiddleware

from __init__ import Tenants
from fastapi import FastAPI
from fastapi.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from auth import authorization, authentication
from api_pods import router as router_pods
from api_pods_podid import router as router_pods_podsid
from api_pods_podid_func import router as router_pods_podsid_func
from api_volumes import router as router_volumes
from api_volumes_volid import router as router_volumes_volumeid
from api_volumes_volid_func import router as router_volumes_volumeid_func
from api_snapshots import router as router_snapshots
from api_snapshots_snapid import router as router_snapshots_snapshotid
from api_snapshots_snapid_func import router as router_snapshots_snapshotid_func
from api_templates import router as router_templates
from api_templates_templateid import router as router_templates_templateid
from api_templates_templateid_tags import router as router_templates_templateid_tags
from api_templates_templateid_func import router as router_templates_templateid_func
from api_images import router as router_images
from api_images_imageid import router as router_images_imageid
from api_misc import router as router_misc


description = """
The Pods Service is a web service and distributed computing platform providing pods-as-a-service (PaaS). The service 
implements a message broker and processor model that requests pods, alongside a health module to poll for pod
data, including logs, status, and health. The primary use of this service is to have quick to deploy long-lived
services based on Docker images that are exposed via HTTP or TCP endpoints listed by the API.

**The Pods service provides functionality for two types of pod solutions:**
 * **Templated Pods** for run-as-is popular images. Neo4J is one example, the template manages TCP ports, user creation, and permissions.
 * **Custom Pods** for arbitrary docker images with less functionality. In this case we will expose port 5000 and do nothing else.

 The live-docs act as the most up-to-date API reference. Visit the [documentation for more information](https://tapis.readthedocs.io/en/latest/technical/pods.html).
"""

tags_metadata = [
    {
        "name": "Pods",
        "description": "Create and command pods.",
    },
    {
        "name": "Credentials",
        "description": "Manage pod's credentials used.",
    },
    {
        "name": "Logs",
        "description": "Manage pod logs.",
    },
    {
        "name": "Permissions",
        "description": "Manage pod permissions. Grant specific TACC users **READ**, **USER**, and **ADMIN** level permissions.",
    },
    {
        "name": "Volumes",
        "description": "Create and manage volumes.",
    },
    {
        "name": "Snapshots",
        "description": "Create and manage snapshots.",
    }

]

api = FastAPI(
    title="Tapis Pods Service",
    description=description,
    openapi_tags=tags_metadata,
    version="1.6.0",
    contact={
        "name": "CIC Support",
        "email": "cicsupport@tacc.utexas.edu",
        "url": "https://tapis-project.org"
    },
    license_info={
        "name": "BSD 3.0",
        "url": "https://github.com/tapis-project/pods_service",
    },
    debug=False,
    exception_handlers={
        Exception: error_handler,
        RequestValidationError: error_handler,
        422: error_handler
    },
    middleware=[
        Middleware(HttpUrlRedirectMiddleware),
        Middleware(GlobalsMiddleware),
        Middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],#, "http://localhost:3001", "localhost:5000", "http://localhost:5000", "localhost"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["X-Tapis-Token", "Origin", "Access-Control-Request-Methods", "*"],
            # I don't think we need X-TapisUsername, it's for auth testing, but it's here.
            expose_headers=["X-TapisUsername", "x-tapis-token", "*"],
            max_age=600),
        Middleware(
            TapisMiddleware,
            tenant_cache=Tenants,
            authn_callback=authentication,
            authz_callback=authorization)
    ])

# misc - must be first due to pods/auth route
api.include_router(router_misc)
# templates
api.include_router(router_templates)
api.include_router(router_templates_templateid)
api.include_router(router_templates_templateid_tags)
api.include_router(router_templates_templateid_func)
# images
api.include_router(router_images)
api.include_router(router_images_imageid)
# snapshots
api.include_router(router_snapshots)
api.include_router(router_snapshots_snapshotid)
api.include_router(router_snapshots_snapshotid_func)
# volumes
api.include_router(router_volumes)
api.include_router(router_volumes_volumeid)
api.include_router(router_volumes_volumeid_func)
# pods
api.include_router(router_pods)
api.include_router(router_pods_podsid)
api.include_router(router_pods_podsid_func)

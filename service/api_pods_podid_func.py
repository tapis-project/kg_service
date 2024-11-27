from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from models_pods import Pod, Password, PodResponse, PodPermissionsResponse, PodCredentialsResponse, PodLogsResponse
from models_misc import SetPermission
from channels import CommandChannel
from codes import OFF, ON, RESTART, REQUESTED, STOPPED
import requests
from tapisservice.tapisfastapi.utils import g, ok
from tapisservice.config import conf
from __init__ import t, BadRequestError
from models_templates_tags import combine_pod_and_template_recursively


from tapisservice.logs import get_logger
logger = get_logger(__name__)

router = APIRouter()


#### /pods/{pod_id}/functionHere

@router.get(
    "/pods/{pod_id}/credentials",
    tags=["Credentials"],
    summary="get_pod_credentials",
    operation_id="get_pod_credentials",
    response_model=PodCredentialsResponse)
async def get_pod_credentials(pod_id):
    """
    Get the credentials created for a pod.

    Note:
    - These credentials are used in the case of templated pods, but for custom pods they're not.

    Returns user accessible credentials.
    """
    logger.info(f"GET /pods/{pod_id}/credentials - Top of get_pod_credentials.")

    # Do more update things.
    password = Password.db_get_with_pk(pod_id, g.request_tenant_id, g.site_id)
    user_cred = {"user_username": password.user_username,
                 "user_password": password.user_password}

    return ok(result=user_cred)


@router.get(
    "/pods/{pod_id}/logs",
    tags=["Logs"],
    summary="get_pod_logs",
    operation_id="get_pod_logs",
    response_model=PodLogsResponse)
async def get_pod_logs(pod_id):
    """
    Get a pods stdout logs and action_logs.
    
    Note:
    - Pod logs are only retrieved while pod is running.
    - If a pod is restarted or turned off and then on, the logs will be reset.
    - Action logs are detailed logs of actions taken on the pod.

    Returns pod stdout logs and action logs.
    """
    logger.info(f"GET /pods/{pod_id}/logs - Top of get_pod_logs.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    return ok(result={"logs": pod.logs, "action_logs": pod.action_logs}, msg = "Pod logs retrieved successfully.")


@router.get(
    "/pods/{pod_id}/permissions",
    tags=["Permissions"],
    summary="get_pod_permissions",
    operation_id="get_pod_permissions",
    response_model=PodPermissionsResponse)
async def get_pod_permissions(pod_id):
    """
    Get a pods permissions.

    Note:
    - There are 3 levels of permissions, READ, USER, and ADMIN.
    - Permissions are granted/revoked to individual TACC usernames.

    Returns all pod permissions.
    """
    logger.info(f"GET /pods/{pod_id}/permissions - Top of get_pod_permissions.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    return ok(result={"permissions": pod.permissions}, msg = "Pod permissions retrieved successfully.")


@router.post(
    "/pods/{pod_id}/permissions",
    tags=["Permissions"],
    summary="set_pod_permission",
    operation_id="set_pod_permission",
    response_model=PodPermissionsResponse)
async def set_pod_permission(pod_id, set_permission: SetPermission):
    """
    Set a permission for a pod.

    Returns updated pod permissions.
    """
    logger.info(f"POST /pods/{pod_id}/permissions - Top of set_pod_permissions.")

    inp_user = set_permission.user
    inp_level = set_permission.level

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    # Get formatted perms
    curr_perms = pod.get_permissions()

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
    pod.permissions = perm_list
    pod.db_update(f"'{g.username}' set permission for '{inp_user}' to {inp_level}")

    return ok(result={"permissions": pod.permissions}, msg = "Pod permissions updated successfully.")


@router.delete(
    "/pods/{pod_id}/permissions/{user}",
    tags=["Permissions"],
    summary="delete_pod_permission",
    operation_id="delete_pod_permission",
    response_model=PodPermissionsResponse)
async def delete_pod_permission(pod_id, user):
    """
    Delete a permission from a pod.

    Returns updated pod permissions.
    """
    logger.info(f"DELETE /pods/{pod_id}/permissions/{user} - Top of delete_pod_permission.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    # Get formatted perms
    curr_perms = pod.get_permissions()

    if user not in curr_perms.keys():
        raise KeyError(f"Could not find permission for pod with username {user} when deleting permission")

    # Delete permission
    del curr_perms[user]

    # Ensure there's still one ADMIN role before finishing.
    if "ADMIN" not in curr_perms.values():
        raise KeyError(f"Operation would result in pod with no users in ADMIN role. Rolling back.")

    # Convert back to db format
    perm_list = []
    for user, level in curr_perms.items():
        perm_list.append(f"{user}:{level}")
    
    # Update pod object and commit
    pod.permissions = perm_list
    pod.db_update(f"'{g.username}' deleted permission for '{user}'")

    return ok(result={"permissions": pod.permissions}, msg = "Pod permission deleted successfully.")


@router.get(
    "/pods/{pod_id}/stop",
    tags=["Pods"],
    summary="stop_pod",
    operation_id="stop_pod",
    response_model=PodResponse)
async def stop_pod(pod_id):
    """
    Stop a pod.

    Note:
    - Sets status_requested to OFF. Pod will attempt to get to STOPPED status unless start_pod is ran.

    Returns updated pod object.
    """
    logger.info(f"GET /pods/{pod_id}/stop - Top of stop_pod.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)
    pod.status_requested = OFF
    pod.db_update(f"'{g.username}' ran stop_pod, set to OFF")
                  
    return ok(result=pod.display(), msg = "Updated pod's status_requested to OFF.")


@router.get(
    "/pods/{pod_id}/start",
    tags=["Pods"],
    summary="start_pod",
    operation_id="start_pod",
    response_model=PodResponse)
async def start_pod(pod_id):
    """
    Start a pod.

    Note:
    - Sets status_requested to ON. Pod will attempt to deploy.

    Returns updated pod object.
    """
    logger.info(f"GET /pods/{pod_id}/start - Top of start_pod.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    # Only run start_pod from status=STOPPED
    if not pod.status in [STOPPED]:
        raise RuntimeError(f"Pod must be in 'STOPPED' status to run 'start_pod'. Please run 'stop_pod' or 'restart_pod' instead.")
    else:
        pod.status_requested = ON
        pod.status = REQUESTED

        # Send command to start new pod
        ch = CommandChannel(name=pod.site_id)
        ch.put_cmd(object_id=pod.pod_id,
                   object_type="pod",
                   tenant_id=pod.tenant_id,
                   site_id=pod.site_id)
        ch.close()
        logger.debug(f"Command Channel - Added msg for pod_id: {pod.pod_id}.")

        pod.db_update(f"'{g.username}' ran start_pod, set to ON and REQUESTED")

    return ok(result=pod.display(), msg = "Updated pod's status_requested to ON and requested pod.")


@router.get(
    "/pods/{pod_id}/restart",
    tags=["Pods"],
    summary="restart_pod",
    operation_id="restart_pod",
    response_model=PodResponse)
async def restart_pod(pod_id):
    """
    Restart a pod.

    Note:
    - Sets status_requested to RESTART. If pod status gets to STOPPED, status_requested will be flipped to ON. Health should then create new pod.

    Returns updated pod object.
    """
    logger.info(f"GET /pods/{pod_id}/restart - Top of restart_pod.")

    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)
    pod.status_requested = RESTART

    pod.db_update(f"'{g.username}' ran restart_pod, set to RESTART")
                  
    return ok(result=pod.display(), msg = "Updated pod's status_requested to RESTART.")


def is_logged_in(cookies):
    """
    Check whether the current session contains a valid login;
    If so: return True, username, roles
    Otherwise: return False, None, None
    """
    logger.debug(f"Checking if logged in: {cookies}")
    if 'X-Tapis-Username' in cookies:
        return True, cookies['X-Tapis-Username'], None
    return False, None, None


def get_username(tapis_domain, token):
    """
    Validate a Tapis JWT, `token`, and resolve it to a username.
    """
    headers = {'Content-Type': 'text/html'}
    # call the userinfo endpoint
    url = f"https://{tapis_domain}/v3/oauth2/userinfo"
    headers = {'X-Tapis-Token': token}
    try:
        rsp = requests.get(url, headers=headers)
        rsp.raise_for_status()
        username = rsp.json()['result']['username']
    except Exception as e:
        raise Exception(f"Error looking up token info; debug: {e}")
    return username



@router.get(
    "/pods/{pod_id_net}/auth",
    tags=["Pods"],
    summary="OAuth2 endpoint to act as middleware between pods and user traffic, checking for authorization on a per pod basis.",
    operation_id="pod_auth",
    response_model=PodResponse)
async def pod_auth(pod_id_net, request: Request):
    """
    Auth endpoint for each pod. When a networking object defines tapis_auth=True, this endpoint manages auth.

    Traefik has a forwardAuth middleware for http routes. This redirects users, auth happens, if traefik gets 200 then traefik allows user to endpoint.
    Auth flow for a user getting to "fastapi hello world" pod at https://fastapi.pods.tacc.tapis.io.
      1) User navigates to https://fastapi.pods.tacc.tapis.io
      2) Traefik redirects user to https://tacc.tapis.io/v3/pods/fastapi/auth
      3) Check if logged in via cookies, if logged in, respond 200 + set user defined headers. Otherwise...
      4) Pods service creates client in correct tenant for user or updates client if it already exists. (we expect only one client in use at a time)
      5) With client the /auth endpoint redirects users to https://tacc.tapis.io/v3/oauth2/authorize?client_id={client_id}&redirect_uri={callback_url}&response_type=code
      6) User logs in via browser, authorizes client, redirects to callback_url at https://tacc.tapis.io/v3/pods/fastapi/auth/callback?code=CodeHere
      7) Callback url exchanges code for token, gets username from token, sets X-Tapis-Token and X-Tapis-Username cookies
      8) User gets redirected back to https://fastapi.pods.tacc.tapis.io, Traefik starts forwardAuth, user at this point should be authenticated
      9) Auth endpoint responds with 200, sets headers specified by networking stanza, and users gets to fastapi hello world response.

    users can specify:
     - tapis_auth=True/False - Turns on auth
     - tapis_auth_response_headers - dict[str] - headers to set on response and their values
     - tapis_auth_allowed_users - list[str] - list of tapis users allowed to access pod
     - tapis_auth_return_path - str - uri to return to after auth, default is "passthrough", which we save in cookies(?) and return to. x-forwarded-host?
    
     - response headers need to be slightly modifiable to allow for different application requirements
     - for example we have to pass username, but many apps require @email.bit, so user must be able to append to user.
     - tapis_auth_response_headers: {"X-Tapis-Username": "<<tapisusername>>@tapis.io", "X-Tapis-Token": "<<token>>", "OAUTH2_USERNAME_KEY": "username"}

     - tapis_auth_allowed_users, checks username against .lower() of username list to make sure it's in list. otherwise deny
    """
    logger.debug(f"GET /pods/{pod_id_net}/auth - pod-auth, headers: {request.headers}, request.cookies: {request.cookies}")
    # In cases where networking key is not 'default', the pod_id_net is f"{pod_id}-{network_key}"
    parts = pod_id_net.split('-', 1)
    pod_id = parts[0]
    network_key = parts[1] if len(parts) > 1 else 'default'

    ## Headers contains x-forwarded stuff we can use to deduct correct tenant (x-forwarded-host)
    ## example data for future reference
    # 'x-forwarded-for': '10.233.72.192'             # doesn't seem like real ip, we're getting proxy server forward info
    # 'x-forwarded-host': 'tacc.develop.tapis.io'
    # 'x-forwarded-port': '80', 'x-forwarded-prefix': '/v3'
    # 'x-forwarded-proto': 'http'
    # 'x-forwarded-server': 'pods-traefik-65c7ccb5fd-ffk4g'
    # 'x-real-ip': '10.233.72.193'    
    
    # if not authenticated, start the OAuth flow
    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)
    
    if pod.template:
        # Derive the final pod object by combining the pod and templates
        final_pod = combine_pod_and_template_recursively(pod, pod.template, tenant=g.request_tenant_id, site=g.site_id)
    else:
        final_pod = pod

    net_info = pod.networking.get(network_key, None)
    if not net_info:
        raise Exception(f"Pod {pod_id} does not have networking key that matches pod_id_net: {pod_id_net}")

    # check if dict
    # net_info
    if type(net_info) is not dict:
        return JSONResponse(content = f"Pod {pod_id} net_info is not a dict, it's a {type(net_info)}", status_code = 500)

    authenticated, xTapisUsername, _ = is_logged_in(request.cookies)
    # if already authenticated, return 200, which will allow the request to continue in Traefik
    if authenticated:
        username = xTapisUsername + "@tapis.io"
        logger.debug(f"GET /pods/{pod_id_net}/auth - pod-auth, already authenticated X-Tapis-Username: {username}")
        #return {'code': 200} #result = {'path':'/', 'code': 302}
        return JSONResponse(content=ok("Already authenticated"), status_code=200, headers={"X-Tapis-Username": username})

    
    # Get info for clients
    # The goal is: https://tacc.develop.tapis.io/v3/pods/{{pod_id}}/auth
    pod_id, tapis_domain = net_info['url'].split('.pods.') ## Should return `mypod` & `tacc.tapis.io` with proper tenant and schmu
    tapis_tenant = tapis_domain.split('.')[0]
    if not net_info["tapis_auth"]:
        return JSONResponse(content = f"This pod does not have tapis_auth configured in networking for this pod_id_net: {pod_id_net}. Leave or remedy.", status_code = 403)        
    
    
    auth_url =  f"https://{tapis_domain}/v3/pods/{pod_id_net}/auth"
    auth_callback_url =  f"https://{tapis_domain}/v3/pods/{pod_id_net}/auth/callback" # should match client callback_url
    tapis_auth_response_headers = net_info["tapis_auth_response_headers"]

    client_id = f"PODS-SERVICE-{pod.k8_name}-{network_key}"
    #client_key = "4STQ^t&RGa$sah!SZ9zCP9UScGoEkS^GYLZDjjtjPBipp4kVLyrr@X"
    client_display_name = f"Tapis Pods Service Pod: {pod_id}"
    client_description = f"Tapis Pods Service Pod: {pod_id}"

    
    logger.debug(f"GET /pods/{pod_id_net}/auth - pod-auth, headers: {request.headers}, request.cookies: {request.cookies}, tenant_id: {g.request_tenant_id}, derived_tenant_id: {tapis_tenant}, site_id: {g.site_id}")
    
    td = None
    # Create tapis client or update tapis client if needed
    try:
        logger.debug(f"Creating client_id: {client_id}, tenant: {tapis_tenant}")
        res, td = t.authenticator.create_client(
            client_id = client_id,
            #client_key = client_key,
            callback_url = auth_callback_url,
            display_name = client_display_name,
            description = client_description,
            _x_tapis_tenant = tapis_tenant,
            _x_tapis_user = "_tapis_pods",
            _tapis_debug = True
        )
    except BadRequestError as e: # Exceptions in 3 shouldn't have e.message (only e.args), but this one does.
        logger.debug(f"Got error creating client: {e.message}")
        if "This change would violate uniqueness constraints" in e.message:
            logger.debug(f"Client already exists, updating client_id: {client_id}, tenant: {tapis_tenant}")
            try:
                res, td = t.authenticator.update_client(
                    client_id = client_id,
                    callback_url = auth_callback_url,
                    display_name = client_display_name,
                    description = client_description,
                    _x_tapis_tenant = tapis_tenant,
                    _x_tapis_user = "_tapis_pods",
                    _tapis_debug = True
                )
                # Assuming you want to return a success response after updating
                success_msg = f"Client {client_id} updated successfully."
                logger.info(success_msg)
            except Exception as e:
                msg = (f"Error updating client_id: {client_id}. e: {e.args}, e: {e}, dir(e): {dir(e)}")
                logger.warning(msg)
                return JSONResponse(content = msg, status_code = 500)
        msg = (f"Error creating client_id: {client_id}. e.message: {e.message}, e.request: {e.request}, e.response: {e.response}, tapis_debug = {td}")
        logger.warning(msg)

#       return JSONResponse(content = msg, status_code = 500)
    oauth2_url = f"https://{tapis_domain}/v3/oauth2/authorize?client_id={client_id}&redirect_uri={auth_callback_url}&response_type=code"
    logger.debug(f"oauth2 url is: {oauth2_url}")
    return RedirectResponse(url=oauth2_url, status_code=302)
    # result = {'path': auth_callback_url, 'code': 302}
    return JSONResponse(content = str(result))

@router.get(
    "/pods/{pod_id_net}/auth/callback",
    tags=["Pods"],
    summary="pod_auth_callback",
    operation_id="pod_auth_callback",
    response_model=PodResponse)
def callback(pod_id_net, request: Request):
    logger.info(f"GET /pods/{pod_id_net}/auth/callback - pod_auth_callback, headers: {request.headers}, request.cookies: {request.cookies}")
    parts = pod_id_net.split('-', 1)
    pod_id = parts[0]
    network_key = parts[1] if len(parts) > 1 else 'default'
    pod = Pod.db_get_with_pk(pod_id, tenant=g.request_tenant_id, site=g.site_id)

    if pod.template:
        # Derive the final pod object by combining the pod and templates
        final_pod = combine_pod_and_template_recursively(pod, pod.template, tenant=g.request_tenant_id, site=g.site_id)
    else:
        final_pod = pod

    net_info = pod.networking.get(network_key, None)
    if not net_info:
        raise Exception(f"Pod {pod_id} does not have networking key that matches pod_id_net: {pod_id_net}")

    pod_id, tapis_domain = net_info['url'].split('.pods.') ## Should return `mypod` & `tacc.tapis.io` with proper tenant and schmu
    tapis_tenant = tapis_domain.split('.')[0]
    if not net_info["tapis_auth"]:
        return JSONResponse(content = f"This pod does not have tapis_auth configured in networking for this pod_id_net: {pod_id_net}. Leave or remedy.", status_code = 403)        

    client_id = f"PODS-SERVICE-{pod.k8_name}-{network_key}"

    try:
        res, td = t.authenticator.get_client(
            client_id = client_id,
            _x_tapis_tenant = tapis_tenant,
            _x_tapis_user = "_tapis_pods",
            _tapis_debug = True)
    except Exception as e:
        return JSONResponse(content=f"Error retrieving client: {e}", status_code=500)
    
    # return JSONResponse(content = f"Callback for pod_id_net: {pod_id_net}, tapis_domain: {tapis_domain}", status_code = 200)
    code = request.query_params.get('code')
    if not code:
        raise Exception(f"Error: No code in request; debug: {request.query_params}")
    logger.debug(f"GET /pods/{pod_id_net}/auth/callback - pod_auth_callback, code: {code}")
    url = f"https://{tapis_domain}/v3/oauth2/tokens"
    data = {
        "code": code,
        "redirect_uri": f"https://{tapis_domain}/v3/pods/{pod_id_net}/auth/callback",
        "grant_type": "authorization_code",
    }

    try:
        logger.debug(dir(res))
        response = requests.post(url, data=data, auth=(client_id, res.client_key))
        response.raise_for_status()
        logger.debug(f"GET /pods/{pod_id_net}/auth/callback callback request response: {response.text}")
        json_resp = response.json()
        #json_resp = json.loads(response.text)
        token = json_resp['result']['access_token']['access_token']
    except Exception as e:
        raise Exception(f"Error generating Tapis token; debug: {e}")

    try:
        logger.debug(f"GET /pods/{pod_id_net}/auth/callback - pod_auth_callback, token: {token}")

        username = get_username(tapis_domain=tapis_domain, token=token)
        
        username = username
        content = {"message": f"Callback for pod_id_net: {pod_id_net}, tapis_domain: {tapis_domain}, username: {username}, token: {token}"}

#        response = JSONResponse(content=content, status_code=200)
#        response = RedirectResponse(url=f"https://{tapis_domain}/v3/pods/{pod_id_net}/auth", status_code=302, headers={"X-Tapis-Username": username, "X-Tapis-Token": token})
        #response = JSONResponse(content=content, status_code=200)
        response = RedirectResponse(url=f"https://{net_info['url']}/auth", status_code=302)

        domain = conf.get('COOKIE_DOMAIN', f"{tapis_domain}")
        logger.debug(f"About to set cookies. domain: {domain}, net_info['url']: {net_info['url']}")

        response.set_cookie("X-Tapis-Token", token, domain=net_info["url"], secure=True)
        response.set_cookie("X-Tapis-Username", username, domain=net_info["url"], secure=True)    

        response.set_cookie("X-Tapis-Token", token, domain=domain, secure=True)
        response.set_cookie("X-Tapis-Username", username, domain=domain, secure=True)    

        logger.debug(f"GET /pods/{pod_id_net}/auth/callback - pod_auth_callback last bit, response: {response}, net_info: {net_info['url']}")

        return response
    except Exception as e:
        raise Exception(f"Error setting cookies; debug: {e}")

    # response = make_response(redirect(os.environ['FRONT_URL'], code=302))

    # domain = conf.get('COOKIE_DOMAIN', f".pods.{tapis_domain}")
    # response.set_cookie("token", token, domain=domain, secure=True)
    # response.set_cookie("username", username, domain=domain, secure=True)    
    
    # return response

    #return JSONResponse(content = f"Callback for pod_id_net: {pod_id_net}, tapis_domain: {tapis_domain}, username: {username}, token: {token}", status_code = 200)
    #return response


import os
import sys
import json
import time
import pytest
from tests.test_utils import headers, response_format, basic_response_checks, delete_pods, t

# Allows us to import pods's modules.
sys.path.append('/home/tapis/service')
from api import api

# Set up client for testing
from fastapi.testclient import TestClient

# base_url: The base URL to use for requests, must be valid Tapis URL.
# raise_server_exceptions: If True, the client will raise exceptions from the server rather the normal client errors.
client = TestClient(api, base_url="https://dev.develop.tapis.io", raise_server_exceptions=False)


# Set up test variables
test_pod_1 = "testnewimages"
test_image_1 = "postgres:14"
test_image_1_no_tag = test_image_1.split(':')[0]
test_image_2 = "tiangolo/uvicorn-gunicorn-fastapi"
test_pod_error_1 = "errorpod"

##### Teardown
@pytest.fixture(scope="module", autouse=True)
def teardown(headers):
    """Delete all Pod service objects created during testing.

    This fixture is automatically invoked by pytest at the end of the test.
    """
    # yield so the fixture waits until the end of the test to continue
    yield None

    # Delete all objects after the tests are done.
    pods = [test_pod_1]
    for pod_id in pods:
        rsp = client.delete(f'/pods/{pod_id}', headers=headers)
    images = [test_image_1_no_tag]
    for image in images:
        rsp = client.delete(f'/pods/images/{image}', headers=headers)


### Testing Images
def test_get_images(headers):
    rsp = client.get("/pods/images", headers=headers)
    result = basic_response_checks(rsp)
    assert result is not None


def test_create_image(headers):
    # Definition
    image_def = {
        "image": test_image_1,
        "tenants": ["*"],
        "description": "Postgres 14 image"
    }
    # Create image
    rsp = client.post("/pods/images", data=json.dumps(image_def), headers=headers)
    
    result = basic_response_checks(rsp)
    rsp_dict = json.loads(rsp.content.decode('utf-8'))
    # Check the image
    assert result['image'] in test_image_1_no_tag # output image should be without tag
    assert rsp_dict['metadata']['notice'] == "removed tag from image, tag enforcement does not yet exist"


def test_check_get_images(headers):
    rsp = client.get("/pods/images", headers=headers)
    result = basic_response_checks(rsp)
    found_img = False
    for image in result:
        if image['image'] in test_image_1_no_tag:
            found_img = True
            break
    assert found_img


def test_get_image(headers):
    rsp = client.get(f"/pods/images/{test_image_1_no_tag}", headers=headers)
    result = basic_response_checks(rsp)
    print(result)
    # Check the pod object
    assert result['image'] in test_image_1_no_tag


# def test_get_permissions(headers):
#     rsp = client.get(f"/pods/volumes/{test_volume_1}/permissions", headers=headers)
#     result = basic_response_checks(rsp)
#     assert result['permissions']

# def test_set_permissions(headers):
#     # Definition
#     perm_def = {
#         "user": "testuser",
#         "level": "READ"
#     }
#     # Create user permission on pod
#     rsp = client.post(f"/pods/volumes/{test_volume_1}/permissions", data=json.dumps(perm_def), headers=headers)
#     result = basic_response_checks(rsp)
#     assert "testuser:READ" in result['permissions']

# def test_delete_set_permissions(headers):
#     user = "testuser"
#     # Delete user permission from pod
#     rsp = client.delete(f"/pods/volumes/{test_volume_1}/permissions/{user}", headers=headers)
#     result = basic_response_checks(rsp)
#     assert "Volume permission deleted successfully" in rsp.json()['message']

# def test_update_image(headers):
#     # Definition
#     vol_def = {
#         "description": "Test volume updated"
#     }
#     # Update volume
#     rsp = client.put(f"/pods/volumes/{test_volume_1}", data=json.dumps(vol_def), headers=headers)
#     result = basic_response_checks(rsp)
#     # Check the volume
#     assert result['volume_id'] == test_volume_1
#     assert result['description'] == "Test volume updated"

# def test_update_volume_no_change(headers):
#     # Definition
#     vol_def = {
#         "description": "Test volume updated"
#     }
#     # Update volume
#     rsp = client.put(f"/pods/volumes/{test_volume_1}", data=json.dumps(vol_def), headers=headers)
#     result = basic_response_checks(rsp)
#     assert rsp.json()['message'] == "Incoming data made no changes to volume. Is incoming data equal to current data?"


def test_create_pod_with_new_image(headers):
    # Definition
    pod_def = {
        "pod_id": test_pod_1,
        "image": test_image_1_no_tag,
        "description": "Postgres 14 pod"
    }
    # Attempt to create pod
    rsp = client.post("/pods", data=json.dumps(pod_def), headers=headers)
    result = basic_response_checks(rsp)

    # Check the pod object
    assert result['pod_id'] == test_pod_1
    assert result['image'] in test_image_1_no_tag


##### Error testing
def test_description_length_400(headers):
    # Definition
    image_def = {
        "image": "test-err-image-1",
        "description": "Test" * 200
    }
    # Attempt to create image
    rsp = client.post("/pods/images", data=json.dumps(image_def), headers=headers)
    data = response_format(rsp)
    # Test error response.
    assert rsp.status_code == 400
    assert any('description field must be less than 255 characters.' in msg for msg in data['message'])


def test_description_is_ascii_400(headers):
    # Definition
    image_def = {
        "image": "test-err-image-2",
        "description": "cafè"
    }
    # Attempt to create image
    rsp = client.post("/pods/images", data=json.dumps(image_def), headers=headers)
    data = response_format(rsp)
    # Test error response.
    assert rsp.status_code == 400
    assert any('description field may only contain ASCII characters' in msg for msg in data['message'])

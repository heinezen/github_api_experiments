#!/usr/bin/env python3

"""
Tests for the Github REST API.
"""

import argparse
import base64
import json
import re
import requests

from tokens import PZ_ALLSCOPES, PZ_GIST, PZ_PASSWORD, PZ_USERNAME

def pretty_print(response):
    """
    Print the request URL, status code, headers and body of a HTTP response.

    :param response: A HTTP response.
    """

    print("---URL---")
    print(response.url)
    print()

    print("---Status Code---")
    print(response.status_code)
    print()

    print("---Headers---")
    for header, payload in response.headers.items():
        print(header + ":", payload)

    print("---Body---")

    try:
        body = response.json()
        print(json.dumps(body, indent=4))

    except:
        body = response.text
        print(body)

def compare(response1, response2):
    """
    Compare two HTTP responses.

    The method will check for equality of
        * URL
        * Status code
        * Headers
        * Body

    of the responses. For HTTP headers and bodys that contain a JSON object
    it will additionally differentiate between
        * Equal headers (Header type and Header payload is equal)
        * Common headers (Header type is equal, payload is different)
        * Unique headers (Header type exists in only one response)

    Results will be printed to the console.

    :param response1: HTTP response 1.
    :param response2: HTTP response 2.
    """

    print("---URLs---")
    print("Equal?:", response1.url == response2.url)
    print("Request 1:", response1.url)
    print("Request 2:", response2.url)
    print()

    print("---Status Codes---")
    print("Equal?:", response1.status_code == response2.status_code)
    print("Response 1:", response1.status_code)
    print("Response 2:", response2.status_code)
    print()

    # Check the headers for equal, common and unique payloads
    equal_headers = {}
    common_headers_response1 = {}
    common_headers_response2 = {}
    unique_headers_response1 = {}
    unique_headers_response2 = {}
    for header1, payload1 in response1.headers.items():
        if header1 in response2.headers.keys():
            payload2 = response2.headers[header1]
            if payload1 == response2.headers[header1]:
                equal_headers[header1] = payload1

            else:
                common_headers_response1[header1] = payload1
                common_headers_response2[header1] = payload2

        else:
            unique_headers_response1[header1] = payload1

    for header2, payload2 in response2.headers.items():
        if header2 not in response1.headers.keys():
            unique_headers_response2[header2] = payload2

    print("---Equal Headers---")
    for header, payload in equal_headers.items():
        print(header + ":", payload)

    print()

    print("---Common Headers Response 1---")
    for header, payload in common_headers_response1.items():
        print(header + ":", payload)

    print()

    print("---Common Headers Response 2---")
    for header, payload in common_headers_response2.items():
        print(header + ":", payload)

    print()

    print("---Unique Headers Response 1---")
    for header, payload in unique_headers_response1.items():
        print(header + ":", payload)

    print()

    print("---Unique Headers Response 2---")
    for header, payload in unique_headers_response2.items():
        print(header + ":", payload)

    print()


    response1_payload = response1.json()
    response2_payload = response2.json()

    # Handle bodies that are not a single JSON object
    if not isinstance(response1_payload, dict) or not isinstance(response2_payload, dict):
        # Just check for equality of payloads without further analysis
        print("---Equal Body Payloads---")
        print("Equal?:", response1_payload == response2_payload)
        print()

        if response1_payload == response2_payload:
            print(json.dumps(response1_payload, indent=4))

        else:
            print("---Payload Response 1---")
            print(json.dumps(response1_payload, indent=4))
            print()
            print("---Payload Response 2---")
            print(json.dumps(response2_payload, indent=4))

        return


    # Check the JSON object in the HTTP body for equal, common and unique payloads
    equal_payloads = {}
    common_payloads_response1 = {}
    common_payloads_response2 = {}
    unique_payloads_response1 = {}
    unique_payloads_response2 = {}
    for key1, val1 in response1_payload.items():
        if key1 in response2_payload.keys():
            val2 = response2_payload[key1]
            if val1 == response2_payload[key1]:
                equal_payloads[key1] = val1

            else:
                common_payloads_response1[key1] = val1
                common_payloads_response2[key1] = val2

        else:
            unique_payloads_response1[key1] = val1

    for key2, val2 in response2_payload.items():
        if key2 not in response1_payload.keys():
            unique_payloads_response2[key2] = val2

    print("---Equal Body Payloads---")
    for key, val in equal_payloads.items():
        print(key + ":", val)

    print()

    print("---Common Body Payloads Response 1---")
    for key, val in common_payloads_response1.items():
        print(key + ":", val)

    print()

    print("---Common Body Payloads Response 2---")
    for key, val in common_payloads_response2.items():
        print(key + ":", val)

    print()

    print("---Unique Body Payloads Response 1---")
    for key, val in unique_payloads_response1.items():
        print(key + ":", val)

    print()

    print("---Unique Body Payloads Response 2---")
    for key, val in unique_payloads_response2.items():
        print(key + ":", val)


def users_endpoint(auth=None):
    """
    Send a GET request to the /users/{username} endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers = {
            "authorization": auth
        }

    return requests.get("https://api.github.com/users/" + PZ_USERNAME, headers=headers)

def zen_endpoint(auth=None):
    """
    Send a GET request to the /zen endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers = {
            "authorization": auth
        }

    return requests.get("https://api.github.com/zen", headers=headers)

def http_endpoint():
    """
    Send a GET request using HTTP instead of HTTPS. Doesn't automatically follow redirects to see
    the Redirect response.

    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    return requests.get("http://api.github.com/users/" + PZ_USERNAME, allow_redirects=False)

def follow_user_endpoint(auth=None):
    """
    Send a PUT request to the /user/following endpoint. This will follow the
    official Github account at https://github.com/github/.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers = {
            "authorization": auth
        }

    return requests.put("https://api.github.com/user/following/github", headers=headers)

def unfollow_user_endpoint(auth=None):
    """
    Send a DELETE request to the /user/following endpoint. This will unfollow the
    official Github account at https://github.com/github/.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers = {
            "authorization": auth
        }

    return requests.delete("https://api.github.com/user/following/github", headers=headers)

def private_repo_check(auth=None):
    """
    Send a GET request to the /repos/{org}/{repo_id} endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/repos/KnackUndBackAG/geldspeicher", headers=headers)

def http_method_post_check(auth=None):
    """
    Send a POST request to the /user endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.post("https://api.github.com/user", headers=headers)

def http_method_put_check(auth=None):
    """
    Send a PUT request to the /user endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.put("https://api.github.com/user", headers=headers)

def allowlist_format_check(auth=None):
    """
    Send a GET request to the /user endpoint. Tries to request an unsupported
    content type (text/plain) for this endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {
        "accept": "text/plain"
    }
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/user", headers=headers)

def legacy_endpoint_check(auth=None):
    """
    Send a GET request to the /authorizations endpoint. This endpoint
    was removed from the API.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/authorizations", headers=headers)

def user_endpoint(auth=None):
    """
    Send a GET request to the /user endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/user", headers=headers)

def user_orgs_endpoint(auth=None):
    """
    Send a GET request to the /user/orgs endpoint.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/user/orgs", headers=headers)

def user_orgs_endpoint_query():
    """
    Send a GET request to the /user/orgs endpoint using a query parameter for authentication.

    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    return requests.get("https://api.github.com/user/orgs?access_token=" + PZ_ALLSCOPES)

def private_repo_endpoint(auth=None):
    """
    Send a GET request to the /repos/{org}/{repo_id} endpoint. The requested repo is private.

    :param auth: Payload for the Authorization Header in the request.
    :type auth: str
    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    headers = {}
    if auth:
        headers.update({
            "authorization": auth
        })

    return requests.get("https://api.github.com/repos/KnackUndBackAG/geldspeicher", headers=headers)

def repo_endpoint_query():
    """
    Send a GET request to the /repos/{org}/{repo_id} endpoint using a query parameter for authentication.
    The requested repo is private.

    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    return requests.get("https://api.github.com/repos/KnackUndBackAG/geldspeicher?access_token=" + PZ_ALLSCOPES)

def check_openapi():
    """
    Search the OpenAPI JSON description for undocumented response types. Endpoint descriptions
    are checked for error status codes which are not present in the "response" object.

    :returns: The resulting HTTP response.
    :rtype: requests.Response
    """
    from openapi import load

    ref = load("api.github.com.json")

    # Regex for error status codes (4XX)
    # This can generate false positives (e.g. if other numbers are present in the description)
    error_code_regex = re.compile(r"4[0-9]{2}")

    for relpath, path_content in ref["paths"].items():
        for method, method_content in path_content.items():
            description = method_content["description"]
            status_codes = error_code_regex.findall(description)

            if not status_codes:
                continue

            undefined_codes = set(status_codes) - set(method_content["responses"].keys())

            if not undefined_codes:
                continue

            print(relpath)
            print(description)
            print(f"Response for status codes {undefined_codes} not defined")
            print()


def parse_args():
    """
    Parse arguments to the script. The script only takes a single int (for the test index)
    as an input.

    :returns: Parsed arguments
    :rtype: Namespace
    """
    parser = argparse.ArgumentParser(description='Compare HTTP requests to the Github API.')
    parser.add_argument('test_index', type=int, help='index of the test')

    return parser.parse_args()

def main():
    """
    Execute test cases based on the test index in the script arguments.

    Test indices explanation
        * 20-25: Various basic tests for retrieving data from noauth/auth endpoints
        * 40-43: Tests for authentication methods and authentication security
        * 50-51: Tests for error handling
        * 60-63: Tests for undocumented API behaviour
    """
    test_index = parse_args().test_index

    if test_index == 0:
        pass

    elif test_index == 20:
        response = users_endpoint()

        pretty_print(response)

    elif test_index == 21:
        auth = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response = user_orgs_endpoint(auth)

        pretty_print(response)

    elif test_index == 22:
        response = zen_endpoint()

        pretty_print(response)

    elif test_index == 23:
        response1 = user_orgs_endpoint()
        auth2 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response2 = user_orgs_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 24:
        response1 = users_endpoint()
        auth2 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response2 = users_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 25:
        auth1 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response1 = user_orgs_endpoint(auth1)
        auth2 = "token " + PZ_ALLSCOPES
        response2 = user_orgs_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 40:
        response = http_endpoint()

        pretty_print(response)

    elif test_index == 41:
        response1 = user_orgs_endpoint()
        auth2 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_GIST).encode('utf-8')), 'utf-8')
        response2 = user_orgs_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 42:
        auth1 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response1 = user_orgs_endpoint(auth1)
        response2 = user_orgs_endpoint_query()

        compare(response1, response2)

    elif test_index == 43:
        auth1 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_ALLSCOPES).encode('utf-8')), 'utf-8')
        response1 = user_orgs_endpoint(auth1)
        auth2 = "Basic " + str(base64.b64encode((PZ_USERNAME + ":" + PZ_PASSWORD).encode('utf-8')), 'utf-8')
        response2 = user_orgs_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 50:
        response1 = private_repo_endpoint()
        auth2 = "token " + PZ_ALLSCOPES
        response2 = private_repo_endpoint(auth2)

        compare(response1, response2)

    elif test_index == 51:
        response = user_endpoint()

        pretty_print(response)

    elif test_index == 60:
        check_openapi()

    elif test_index == 61:
        auth = "token " + PZ_ALLSCOPES
        response = http_method_post_check(auth)

        pretty_print(response)

    elif test_index == 62:
        response = http_method_post_check()

        pretty_print(response)

    elif test_index == 63:
        auth = "token " + PZ_ALLSCOPES
        response = http_method_put_check(auth)

        pretty_print(response)

    else:
        print(f"No valid test with index {test_index} found")

if __name__ == "__main__":
    main()

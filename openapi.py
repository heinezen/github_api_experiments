

import json

def load(file):
    """
    Load an OpenAPI description in JSON format from file.

    :param file: Filename of a JSON file containing the OpenAPI description.
    :type file: str
    """
    content = {}

    with open(file) as f:
        content = json.loads(f.read())

    return content

import functions_framework
import os
from google.auth import default
import base64
from googleapiclient.discovery import build
import json
from google.cloud import secretmanager
import google.cloud.logging
import logging
# new comment
logging_client = google.cloud.logging.Client()
logging_client.setup_logging()

_, project_id = default()
service_account_email = os.environ.get("SA_EMAIL")
service_account_name = os.environ.get("SA_NAME")
service = build('iam', 'v1')
client = secretmanager.SecretManagerServiceClient()
secret_id = os.environ.get("secret_id")


def create_key():
    key_request = service.projects().serviceAccounts().keys().create(
        name=f'projects/{project_id}/serviceAccounts/{service_account_email}', body={})
    key_response = key_request.execute()
    key = base64.b64decode(key_response['privateKeyData'])
    return key


def delete_older_keys(key_response):
    keys_list = service.projects().serviceAccounts().keys().list(
        name=f'projects/{project_id}/serviceAccounts/{service_account_email}')
    keys = keys_list.execute().get('keys', [])
    key_ids = []
    new_key_id = json.loads(key_response)["private_key_id"]
    for key in keys:
        key_id = key['name'].split("/")[5]
        if key['keyType'] != 'SYSTEM_MANAGED' and key_id != new_key_id and key_id != "2dab73c7e738258337fd27fe44ba0ca59e37df64":
            key_ids.append(key['name'])
            request = service.projects().serviceAccounts().keys().delete(name=key["name"])
            request.execute()
            logging.info(f"Deleted Key {key['name']}")


def get_secret():
    name = client.secret_path(project_id, secret_id)
    try:
        response = client.get_secret(request={"name": name})
        if response and response.name:
            logging.info(f"Secret {secret_id} exists")
            return True
    except Exception as e:
        logging.warning("Secret does not exists...Creating Secret")
        logging.info(e)
    return False


def create_new_secret():
    parent = f"projects/{project_id}"
    secret = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )
    logging.info(f"Created secret: {secret.name}")
    return secret


def add_secret_version(payload):
    parent = client.secret_path(project_id, secret_id)
    payload_bytes = payload.encode("UTF-8")
    version = client.add_secret_version(
        request={
            "parent": parent,
            "payload": {
                "data": payload_bytes,
            },
        }
    )
    logging.info(f"Added secret version: {version.name}")
    return version


def list_last_secret_versions():
    parent = client.secret_path(project_id, secret_id)
    filter_str: str = "state:ENABLED"
    versions = [version for version in client.list_secret_versions(request={"parent": parent, "filter": filter_str})]
    return versions


def destroy_secret_version(version_name):
    response = client.destroy_secret_version(request={"name": version_name})

    logging.info(f"Destroyed secret version: {response.name}")
    return response


@functions_framework.http
def main(request):
    key_data = create_key()
    key = key_data.decode()
    secret_exists = get_secret()
    if secret_exists:
        logging.info("Secret exists")
        last_versions = list_last_secret_versions()
        if last_versions:
            logging.info(len(last_versions))
            created_version = add_secret_version(key)
            if created_version:
                logging.info("Destroying previous versions")
                for last_version in last_versions:
                    dest_version = destroy_secret_version(last_version.name)
                    if dest_version:
                        logging.info(f"Successfully deleted prev version {dest_version.name}")
    else:
        logging.info("Secret needs to be created")
        created_secret = create_new_secret()
        if created_secret:
            created_version = add_secret_version(key)
            if created_version:
                logging.info("First Secret version created")
    delete_older_keys(key_data)

    return f'Successfully rotated key for {service_account_name} service account... '

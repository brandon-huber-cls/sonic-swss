import argparse
import glob
import requests
import json
import os
import subprocess
import hashlib
from pathlib import Path


SAIREDIS = 'sonic-sairedis'
COMMON = 'sonic-common-libs'
SWSSCOMMON = 'sonic-swsscommon'
BUILDIMAGE = 'sonic-buildimage'
VPP = 'sonic-platform-vpp'
DASH_API = 'sonic-dash-api'

# These values are obtained from the pipeline URLs, e.g. the pipeline for swsscommon is https://dev.azure.com/mssonic/build/_build?definitionId=9
pipeline_id_map = {
    SAIREDIS: 12,
    COMMON: 465,
    SWSSCOMMON: 9,
    BUILDIMAGE: 142,
    VPP: 1016,
    DASH_API: 1318
}

pipeline_artifact_map = {
    SAIREDIS: 'sonic-sairedis-{}',
    COMMON: 'common-lib',
    SWSSCOMMON: 'sonic-swss-common-{}',
    BUILDIMAGE: 'sonic-buildimage.vs',
    VPP: 'VPP',
    DASH_API: 'sonic-dash-api'
}

deb_files_regex = ['libswsscommon*.deb', 'libnl*.deb', 'libsai*.deb', 'syncd-vs*.deb', 'libyang3_*.deb', 'libyang-dev_3*.deb', 'python3-swsscommon*.deb', '*vpp*.deb', 'libdash*.deb']

pipeline_out_file_map = {
    SAIREDIS: 'sairedis.zip',
    COMMON: 'common-lib.zip',
    SWSSCOMMON: 'swsscommon.zip',
    VPP: 'vpp.zip',
    DASH_API: 'dash-api.zip'
}

force_main_branch = [VPP]

build_url = 'https://dev.azure.com/mssonic/build/_apis/build/builds?definitions={}&branchName=refs/heads/{}&resultFilter=succeeded,partiallySucceeded&statusFilter=completed&maxBuildsPerDefinition=1&queryOrder=finishTimeDescending'
artifact_url = 'https://dev.azure.com/mssonic/build/_apis/build/builds/{}/artifacts?artifactName={}&api-version=5.1'


def calculate_sha256(filepath):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_artifact_checksum(build_id):
    """Retrieve artifact checksums from the build metadata."""
    checksum_url = f'https://dev.azure.com/mssonic/build/_apis/build/builds/{build_id}?api-version=5.1'
    try:
        res = requests.get(checksum_url, timeout=30)
        if res.status_code == 200:
            build_data = json.loads(res.content)
            # Try to extract checksums from build properties or tags if available
            if 'properties' in build_data and 'artifactChecksums' in build_data['properties']:
                return build_data['properties']['artifactChecksums']
    except Exception as e:
        print(f"Warning: Could not retrieve checksums from build metadata: {e}")
    return None


def verify_artifact_integrity(filepath, expected_checksum=None):
    """Verify the integrity of downloaded artifact using SHA256 checksum."""
    if not os.path.exists(filepath):
        raise Exception(f"Artifact file not found: {filepath}")
    
    actual_checksum = calculate_sha256(filepath)
    
    # If expected checksum is provided, verify against it
    if expected_checksum:
        if actual_checksum.lower() != expected_checksum.lower():
            raise Exception(
                f"Integrity verification failed for {filepath}. "
                f"Expected: {expected_checksum}, Got: {actual_checksum}"
            )
        print(f"Integrity verification passed for {filepath}")
        return True
    else:
        # Log the checksum for manual verification or future pinning
        print(f"Warning: No expected checksum provided for {filepath}")
        print(f"Calculated SHA256: {actual_checksum}")
        print("Consider pinning this checksum for future verification")
        return True


def get_latest_build(pipeline, branch):
    if pipeline in force_main_branch:
        target_branch = "main"
    else:
        target_branch = branch

    url = build_url.format(pipeline_id_map[pipeline], target_branch)
    print(url)
    res = requests.get(url, timeout=30)
    if res.status_code != 200:
        raise Exception(f"Failed to fetch build info for {pipeline} on branch {target_branch}: HTTP {res.status_code}")
    build_info = json.loads(res.content)
    if not build_info.get('value') and target_branch == "master":
        url = build_url.format(pipeline_id_map[pipeline], "main")
        print(url)
        res = requests.get(url, timeout=30)
        if res.status_code != 200:
            raise Exception(f"Failed to fetch build info for {pipeline} on branch main: HTTP {res.status_code}")
        build_info = json.loads(res.content)
    if not build_info.get('value'):
        raise Exception(f"No successful builds found for {pipeline} on branch {target_branch}")
    return build_info['value'][0]['id']


def get_artifact_url(pipeline, build_id, debian_version):
    if pipeline in [SAIREDIS, SWSSCOMMON]:
        artifact_name = pipeline_artifact_map[pipeline].format(debian_version)
    else:
        artifact_name = pipeline_artifact_map[pipeline]
    url = artifact_url.format(build_id, artifact_name)
    print(url)
    res = requests.get(url, timeout=30)
    if res.status_code != 200:
        raise Exception(
            f"Failed to fetch artifact info for {pipeline} (build {build_id}, artifact {artifact_name}): HTTP {res.status_code}"
        )
    artifact_info = json.loads(res.content)
    return artifact_info['resource']['downloadUrl']


def download_artifact(pipeline, filename, branch, debian_version):
    build_id = get_latest_build(pipeline, branch)
    download_url = get_artifact_url(pipeline, build_id, debian_version)
    print("URL: {}".format(download_url))

    # Download with HTTPS verification enabled
    with open(filename, 'wb') as out_file:
        res = requests.get(download_url, stream=True, timeout=60, verify=True)
        res.raise_for_status()
        content = res.content
        out_file.write(content)
    
    # Retrieve and verify checksums if available
    checksums = get_artifact_checksum(build_id)
    expected_checksum = None
    if checksums and pipeline in checksums:
        expected_checksum = checksums[pipeline]
    
    # Verify artifact integrity
    verify_artifact_integrity(filename, expected_checksum)


def get_all_artifacts(dest_dir, branch, debian_version):
    for pipeline, filename in pipeline_out_file_map.items():
        print("Getting artifact {}".format(pipeline))
        dest_file = os.path.join(dest_dir, filename)
        download_artifact(pipeline, dest_file, branch, debian_version)
        print("Finished getting artifact {}".format(pipeline))


def main(branch, debian_version):
    try:
        work_dir = Path("/tmp/sonic/")
        work_dir.mkdir(parents=True, exist_ok=True)

        get_all_artifacts(str(work_dir), branch, debian_version)

        for filename in pipeline_out_file_map.values():
            print("Extracting {}".format(filename))
            filepath = os.path.join(work_dir, filename)
            
            # Verify the file exists before extraction
            if not os.path.exists(filepath):
                raise Exception(f"Artifact file not found for extraction: {filepath}")
            
            if "common-lib" in filename:
                cmd = ['bash', '-c', f"unzip -l {filename} | grep -oE 'common-lib/target/debs/{debian_version}.*deb$' | xargs unzip -o -j {filename}"]
            else:
                cmd = ['unzip', '-o', '-j', filename]

            subprocess.run(cmd, cwd=work_dir, stdout=subprocess.DEVNULL, check=True)

        debs_to_install = []
        for pattern in deb_files_regex:
            debs_to_install += [os.path.join(".", x) for x in glob.glob(pattern, root_dir=work_dir)]

        if not debs_to_install:
            raise Exception("No .deb packages found to install")

        cmd = ["sudo", "env", "VPP_INSTALL_SKIP_SYSCTL=1", "/usr/bin/apt-get", "install", "-y"] + debs_to_install
        subprocess.run(cmd, cwd=work_dir, stdout=subprocess.DEVNULL, check=True)
    except Exception:
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser('SWSS Build Setup')
    parser.add_argument('-b', '--branch', default="master")
    parser.add_argument('-d', '--debian-version', default="bookworm")

    args = parser.parse_args()
    main(args.branch, args.debian_version)
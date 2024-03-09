from jinja2 import Template
import re
import yaml
import sys

# Read YAML content from file
yaml_content = open(sys.argv[1], "r").read()

# Define hardcoded env variables
values = {
    "secrets": {"AWS_ACCOUNT_ID": "123456789123"},
    "env": {
        "AWS_REGION": "us-west-2",
        "ECR_REGISTRY": "123456789123.dkr.ecr.us-west-2.amazonaws.com",
        "ECR_REPOSITORY": "cs40",
    },
    "steps": {"timestamp": {"outputs": {"timestamp": "1709649832"}}},
}

# Rendering the template
template = Template(yaml_content)
rendered_yaml = template.render(**values)

# for the people who hardcoded stuff and didn't reference the environment variables
rendered_yaml = re.sub(r"\b\d{12}\b", "123456789123", rendered_yaml).replace("$", "")

steps = yaml.safe_load(rendered_yaml)["jobs"]["build-and-push"]["steps"]

if steps[5]["with"]["push"] != False:
    print("Step 6 should not push the built images")
tags = re.split("\n|,", steps[5]["with"]["tags"])
if len(tags) > 0 and tags[0][0] == "-":
    tags = [tag[1:] for tag in tags]
tags = [tag.strip() for tag in tags if tag]
if (
    len(tags) != 2
    or "123456789123.dkr.ecr.us-west-2.amazonaws.com/cs40:latest" not in tags
    or not "123456789123.dkr.ecr.us-west-2.amazonaws.com/cs40:1709649832" in tags
):
    print("Step 6 tags are malformed")
if (
    not steps[6]["run"].strip().startswith("aws ecr batch-delete-image")
    or "imageTag=latest" not in steps[6]["run"]
):
    print("Step 7 latest image is not being properly removed")
if "push" in steps[7]["with"] and steps[7]["with"]["push"] != True:
    print("Step 8 should not push the built images")
tags = steps[7]["with"]["tags"].split(",")
if (
    len(tags) != 2
    or "123456789123.dkr.ecr.us-west-2.amazonaws.com/cs40:latest" not in tags
    or not "123456789123.dkr.ecr.us-west-2.amazonaws.com/cs40:1709649832" in tags
):
    print("Step 8 tags are malformed")

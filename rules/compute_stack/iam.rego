package rules

import future.keywords

main := {
	"pass": count(fail) == 0,
	"violations": fail,
}

# Role can only be assumed by specific conditions
fail contains msg if {
	roles := [role | role := input.Resources[_]; role.Type == "AWS::IAM::Role"; role.Properties.AssumeRolePolicyDocument.Statement[0].Action == "sts:AssumeRoleWithWebIdentity"]
	count(roles) != 1

	conditions := {cond | cond := roles[_].Properties.AssumeRolePolicyDocument.Statement[_].Condition.StringEquals}

	pattern := "^repo:[A-Za-z0-9-]*/[A-Za-z0-9-]*:ref:refs/heads/main$"

	not re_match(pattern, conditions["token.actions.githubusercontent.com:sub"])
	not conditions["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"

	msg := sprintf("Role principles improperly configured", [])
}

# Max session duration should be 3600
fail contains msg if {
	roles := [role | role := input.Resources[_]; role.Type == "AWS::IAM::Role"; role.Properties.AssumeRolePolicyDocument.Statement[0].Action == "sts:AssumeRoleWithWebIdentity"]
	count(roles) != 1
	session_duration := roles[_].Properties.MaxSessionDuration
	session_duration != 3600
	msg := sprintf("Max session duration should be one hour", [])
}

# Role should ONLY have access to AmazonEC2ContainerRegistryFullAccess and AmazonECS_FullAccess
fail contains msg if {
	roles := [role | role := input.Resources[_]; role.Type == "AWS::IAM::Role"; role.Properties.AssumeRolePolicyDocument.Statement[_].Action == "sts:AssumeRoleWithWebIdentity"]
	count(roles) != 1
	tokenSub := json.Unmarshal(role.Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]);
	tokenAud := json.Unmarshal(role.Properties.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"]);

	tokenSub == "repo:infracourse/yoctogram-app-private:ref:refs/heads/main" &&
	tokenAud == "sts.amazonaws.com" &&
	action == "sts:AssumeRoleWithWebIdentity"
	msg := sprintf("Role should ONLY have access to AmazonEC2ContainerRegistryFullAccess and AmazonECS_FullAccess", [])
}

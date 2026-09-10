package authz

import future.keywords.in

default allow = false

allow {
	input.user == "admin"
}

deny[msg] {
	msg := "nope"
}

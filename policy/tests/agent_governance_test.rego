# Run:  opa test policy/ -v
#
# Proves the §7 required properties. `data.json` in policy/ is loaded
# automatically by `opa test policy/`.
package dciso.governance_test

import data.dciso.governance

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
soft_allow := {
	"advice": "ALLOW",
	"risk_score": 5,
	"risk_level": "LOW",
	"reason_codes": [],
	"explanation": "looks fine",
	"suggested_obligations": {},
	"availability": "OK",
}

soft_deny_critical := {
	"advice": "DENY",
	"risk_score": 95,
	"risk_level": "CRITICAL",
	"reason_codes": ["EXFIL"],
	"explanation": "no",
	"suggested_obligations": {},
	"availability": "OK",
}

base_tool_event := {
	"schema_version": "0.1.0",
	"event_id": "evt-1",
	"timestamp": "2026-09-01T00:00:00Z",
	"event_type": "tool.execute.proposed",
	"enforcement_phase": "model_response_pre_execution",
	"source": {
		"harness_type": "hermes",
		"harness_instance_id": "hermes-business-01",
		"agent_id": "main-agent",
		"session_id": "sess-1",
	},
	"task": {
		"task_id": "task-1",
		"parent_task_id": null,
		"purpose": "demo",
		"data_classification": ["internal"],
	},
	"proposed_action": {
		"native_name": "read_file",
		"canonical_name": "read_file",
		"arguments": {},
		"resource": null,
		"destination": null,
	},
	"governance": {
		"requested_autonomy": "L1",
		"capability_level": "C1",
		"odd_state": "NORMAL",
		"subagent_depth": 0,
		"parent_grant": null,
		"soft_advice": soft_allow,
		"policy_version": null,
	},
}

base_spawn_event := object.union(base_tool_event, {
	"event_type": "agent.spawn",
	"proposed_action": {
		"native_name": "delegate_task",
		"canonical_name": "agent.spawn",
		"arguments": {"allowed_tools": ["read_file"]},
		"resource": null,
		"destination": null,
	},
})

with_action(evt, action) := object.union(evt, {"proposed_action": object.union(evt.proposed_action, action)})

with_gov(evt, gov) := object.union(evt, {"governance": object.union(evt.governance, gov)})

with_task(evt, task) := object.union(evt, {"task": object.union(evt.task, task)})

# --------------------------------------------------------------------------- #
# 1. safe read-only request -> ALLOW
# --------------------------------------------------------------------------- #
test_safe_read_only_allow if {
	d := governance.decision with input as base_tool_event
	d.decision == "ALLOW"
	d.reason_codes == ["POLICY_ALLOW"]
}

# --------------------------------------------------------------------------- #
# 2. CISO says ALLOW but PHI + external destination -> DENY (§7 rule 2, proof 1)
# --------------------------------------------------------------------------- #
test_phi_external_denied_despite_soft_allow if {
	evt := with_task(
		with_action(base_tool_event, {"canonical_name": "http_request", "native_name": "http_request", "destination": "https://evil.example.com"}),
		{"data_classification": ["PHI"]},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
	"EXTERNAL_SENSITIVE_TRANSFER_DENIED" in d.reason_codes
}

# approved internal destination with PHI is NOT auto-denied by rule 2
test_phi_internal_destination_not_rule2_denied if {
	evt := with_task(
		with_action(base_tool_event, {"canonical_name": "read_file", "destination": "internal://approved-store"}),
		{"data_classification": ["PHI"]},
	)
	d := governance.decision with input as evt
	not "EXTERNAL_SENSITIVE_TRANSFER_DENIED" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 2c. ACS information-flow "no write down"
# --------------------------------------------------------------------------- #
test_ifc_confidential_to_external_denied if {
	evt := with_task(
		with_action(base_tool_event, {"canonical_name": "read_file", "destination": "https://x.example.com"}),
		{"data_classification": ["PII"]},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
	"IFC_CLEARANCE_VIOLATION" in d.reason_codes
}

test_ifc_internal_data_to_external_ok if {
	evt := with_action(base_tool_event, {"canonical_name": "read_file", "destination": "https://x.example.com"})
	d := governance.decision with input as evt
	not "IFC_CLEARANCE_VIOLATION" in d.reason_codes
}

test_ifc_confidential_to_approved_internal_ok if {
	evt := with_task(
		with_action(base_tool_event, {"canonical_name": "read_file", "destination": "internal://approved-store"}),
		{"data_classification": ["PHI"]},
	)
	d := governance.decision with input as evt
	not "IFC_CLEARANCE_VIOLATION" in d.reason_codes
}

test_ifc_secret_to_approved_internal_still_denied if {
	evt := with_task(
		with_action(base_tool_event, {"canonical_name": "read_file", "destination": "internal://approved-store"}),
		{"data_classification": ["SECRET"]},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
	"IFC_CLEARANCE_VIOLATION" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 2d. shell command-level policy
# --------------------------------------------------------------------------- #
test_shell_readonly_command_allowed if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"command": "ls -la /home/user/hello"}})
	d := governance.decision with input as evt
	d.decision == "ALLOW"
}

test_shell_cat_allowed if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"cmd": "cat notes.txt"}})
	d := governance.decision with input as evt
	d.decision == "ALLOW"
}

test_shell_rm_denied if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"command": "rm -rf /home/user/hello"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"DANGEROUS_SHELL_COMMAND:rm" in d.reason_codes
}

test_shell_readonly_binary_with_metachar_not_allowed if {
	# `ls; rm -rf /` starts read-only but has a metachar and a blocked substring
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"command": "ls -la ; rm -rf /"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
}

test_shell_ambiguous_command_needs_review if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"command": "python train.py"}})
	d := governance.decision with input as evt
	d.decision == "REQUIRE_REVIEW"
	"SHELL_COMMAND_NEEDS_REVIEW" in d.reason_codes
}

test_bare_terminal_no_command_denied if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {}})
	d := governance.decision with input as evt
	d.decision == "DENY"
}

test_non_shell_dangerous_tool_still_denied if {
	evt := with_action(base_tool_event, {"canonical_name": "credential_access", "native_name": "credential_access"})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"DANGEROUS_TOOL_DENIED:credential_access" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 3. dangerous tool -> DENY (§7 rule 5)
# --------------------------------------------------------------------------- #
test_terminal_denied if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal"})
	d := governance.decision with input as evt
	d.decision == "DENY"
}

# --------------------------------------------------------------------------- #
# 4. unknown tool fails closed (§7 rule 6, proof 4)
# --------------------------------------------------------------------------- #
test_unknown_tool_fail_closed if {
	evt := with_action(base_tool_event, {"canonical_name": "quantum_teleport", "native_name": "quantum_teleport"})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"UNKNOWN_TOOL" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 5. unknown harness -> DENY (§7 rule 6)
# --------------------------------------------------------------------------- #
test_unknown_harness_denied if {
	evt := object.union(base_tool_event, {"source": object.union(base_tool_event.source, {"harness_type": "openclaw"})})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"UNKNOWN_HARNESS" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 6. incompatible schema version -> DENY (§7 rule 6)
# --------------------------------------------------------------------------- #
test_bad_schema_version_denied if {
	evt := object.union(base_tool_event, {"schema_version": "9.9.9"})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"SCHEMA_VERSION_UNSUPPORTED" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 7. spawn autonomy over ceiling, downgradable -> MODIFY (§7 rule 3)
# --------------------------------------------------------------------------- #
test_spawn_over_ceiling_downgrades_to_modify if {
	evt := with_gov(base_spawn_event, {"requested_autonomy": "L4", "capability_level": "C2"})
	d := governance.decision with input as evt
	d.decision == "MODIFY"
	"AUTONOMY_DOWNGRADED_TO_CEILING" in d.reason_codes
	d.obligations.max_autonomy == "L2"
}

# 7b. ceiling is C0/L0 -> no safe downgrade -> REQUIRE_REVIEW
test_spawn_over_ceiling_no_downgrade_review if {
	evt := with_gov(base_spawn_event, {"requested_autonomy": "L3", "capability_level": "C0"})
	d := governance.decision with input as evt
	d.decision == "REQUIRE_REVIEW"
	"AUTONOMY_OVER_CEILING_NO_SAFE_DOWNGRADE" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 8. parent not allowed to spawn -> child cannot be created (§7 rule 4, proof 2)
# --------------------------------------------------------------------------- #
test_parent_may_not_spawn if {
	evt := with_gov(base_spawn_event, {
		"requested_autonomy": "L1",
		"capability_level": "C2",
		"subagent_depth": 0,
		"parent_grant": {
			"max_autonomy": "L1",
			"max_subagent_depth": 0,
			"allowed_tools": ["read_file"],
			"denied_tools": [],
			"data_scope": [],
			"ttl_seconds": null,
		},
	})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"PARENT_MAY_NOT_SPAWN" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 9. child cannot get more tools than parent (§7 rule 4, proof 3)
# --------------------------------------------------------------------------- #
test_child_cannot_exceed_parent_tools if {
	evt := with_gov(
		with_action(base_spawn_event, {"arguments": {"allowed_tools": ["read_file", "terminal"]}}),
		{
			"requested_autonomy": "L1",
			"capability_level": "C2",
			"subagent_depth": 0,
			"parent_grant": {
				"max_autonomy": "L2",
				"max_subagent_depth": 2,
				"allowed_tools": ["read_file"],
				"denied_tools": ["terminal"],
				"data_scope": [],
				"ttl_seconds": null,
			},
		},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
	"CHILD_GRANT_EXCEEDS_PARENT" in d.reason_codes
}

# 9b. child within parent grant -> ALLOW, obligations reflect narrowed tools
test_child_within_parent_grant_allow if {
	evt := with_gov(
		with_action(base_spawn_event, {"arguments": {"allowed_tools": ["read_file"]}}),
		{
			"requested_autonomy": "L1",
			"capability_level": "C2",
			"subagent_depth": 0,
			"parent_grant": {
				"max_autonomy": "L2",
				"max_subagent_depth": 2,
				"allowed_tools": ["read_file", "search"],
				"denied_tools": ["terminal"],
				"data_scope": [],
				"ttl_seconds": null,
			},
		},
	)
	d := governance.decision with input as evt
	d.decision == "ALLOW"
	d.obligations.allowed_tools == ["read_file"]
	d.obligations.max_subagent_depth == 1
}

# --------------------------------------------------------------------------- #
# 10. soft ALLOW must not loosen; soft DENY(critical) tightens (§7 rule 7, proof)
# --------------------------------------------------------------------------- #
test_soft_allow_does_not_loosen_terminal if {
	evt := with_gov(
		with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal"}),
		{"soft_advice": soft_allow},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
}

test_soft_deny_critical_forces_deny_on_otherwise_allow if {
	evt := with_gov(base_tool_event, {"soft_advice": soft_deny_critical})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"SOFT_ADVICE_DENY_CRITICAL" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 11. soft advice UNAVAILABLE + sensitive -> DENY; + non-sensitive -> ALLOW
#     (§10 Task 4 fail-closed contract)
# --------------------------------------------------------------------------- #
test_soft_unavailable_sensitive_denied if {
	evt := with_gov(
		with_task(base_tool_event, {"data_classification": ["PII"]}),
		{"soft_advice": {"advice": "DENY", "risk_score": 100, "risk_level": "CRITICAL", "reason_codes": ["SOFT_ADVICE_UNAVAILABLE"], "explanation": "timeout", "suggested_obligations": {}, "availability": "UNAVAILABLE"}},
	)
	d := governance.decision with input as evt
	d.decision == "DENY"
	"SOFT_ADVICE_UNAVAILABLE_SENSITIVE" in d.reason_codes
}

test_soft_unavailable_nonsensitive_allowed if {
	evt := with_gov(base_tool_event, {"soft_advice": {"advice": "DENY", "risk_score": 100, "risk_level": "CRITICAL", "reason_codes": ["SOFT_ADVICE_UNAVAILABLE"], "explanation": "timeout", "suggested_obligations": {}, "availability": "UNAVAILABLE"}})
	d := governance.decision with input as evt
	d.decision == "ALLOW"
}

# --------------------------------------------------------------------------- #
# 12. policy version is emitted for the audit log (§7 proof 5)
# --------------------------------------------------------------------------- #
test_policy_version_in_output if {
	d := governance.decision with input as base_tool_event
	d.policy_version == "v0.1.0"
}

# --------------------------------------------------------------------------- #
# 13. review-required tool -> REQUIRE_REVIEW
# --------------------------------------------------------------------------- #
test_send_email_requires_review if {
	evt := with_action(base_tool_event, {"canonical_name": "send_email", "native_name": "send_email"})
	d := governance.decision with input as evt
	d.decision == "REQUIRE_REVIEW"
}

# --------------------------------------------------------------------------- #
# 14. output-side governance (Phase A) — model answer before delivery
# --------------------------------------------------------------------------- #
base_output_event := object.union(base_tool_event, {
	"event_type": "model.output.proposed",
	"enforcement_phase": "model_output_pre_delivery",
	"proposed_action": {
		"native_name": "model_output",
		"canonical_name": "model_output",
		"arguments": {"credential_hits": 0, "forbidden_hits": 0, "recipient_class": "user"},
		"resource": null,
		"destination": null,
	},
})

test_output_clean_allows if {
	d := governance.decision with input as base_output_event
	d.decision == "ALLOW"
}

test_output_credential_hit_modifies_to_redact if {
	evt := with_action(base_output_event, {"arguments": {"credential_hits": 2, "forbidden_hits": 0, "recipient_class": "user"}})
	d := governance.decision with input as evt
	d.decision == "MODIFY"
	"REDACT_OUTPUT_CREDENTIAL" in d.reason_codes
}

test_output_forbidden_marker_denies if {
	evt := with_action(base_output_event, {"arguments": {"credential_hits": 0, "forbidden_hits": 1, "recipient_class": "user"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"FORBIDDEN_DISCLOSURE" in d.reason_codes
}

test_output_internal_data_to_external_recipient_denies if {
	evt1 := with_action(base_output_event, {"arguments": {"credential_hits": 0, "forbidden_hits": 0, "recipient_class": "external"}})
	evt := with_task(evt1, {"data_classification": ["internal"]})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"OUTPUT_RECIPIENT_NOT_CLEARED" in d.reason_codes
}

test_output_public_data_to_external_recipient_allows if {
	evt1 := with_action(base_output_event, {"arguments": {"credential_hits": 0, "forbidden_hits": 0, "recipient_class": "external"}})
	evt := with_task(evt1, {"data_classification": ["public"]})
	d := governance.decision with input as evt
	d.decision == "ALLOW"
}

# --------------------------------------------------------------------------- #
# 15. egress governance (Phase B) — tool result before it reaches a model
# --------------------------------------------------------------------------- #
base_egress_event := object.union(base_tool_event, {
	"event_type": "tool.result.proposed",
	"enforcement_phase": "tool_result_pre_send",
	"proposed_action": {
		"native_name": "tool_result",
		"canonical_name": "tool_result",
		"arguments": {"dest_class": "local", "credential_hits": 0, "forbidden_hits": 0, "sensitive_field_hits": 0, "oversize": false},
		"resource": null,
		"destination": null,
	},
})

test_egress_local_clean_allows if {
	d := governance.decision with input as base_egress_event
	d.decision == "ALLOW"
}

test_egress_credential_redacted_for_local if {
	evt := with_action(base_egress_event, {"arguments": {"dest_class": "local", "credential_hits": 1, "forbidden_hits": 0, "sensitive_field_hits": 0, "oversize": false}})
	d := governance.decision with input as evt
	d.decision == "MODIFY"
	"EGRESS_REDACT_CREDENTIAL" in d.reason_codes
}

test_egress_forbidden_marker_blocked_for_external if {
	evt := with_action(base_egress_event, {"arguments": {"dest_class": "external", "credential_hits": 0, "forbidden_hits": 1, "sensitive_field_hits": 0, "oversize": false}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"EGRESS_FORBIDDEN_MARKER" in d.reason_codes
}

test_egress_forbidden_marker_not_blocked_for_local if {
	evt := with_action(base_egress_event, {"arguments": {"dest_class": "local", "credential_hits": 0, "forbidden_hits": 1, "sensitive_field_hits": 0, "oversize": false}})
	d := governance.decision with input as evt
	d.decision == "ALLOW"
}

test_egress_sensitive_task_blocked_to_external if {
	evt1 := with_action(base_egress_event, {"arguments": {"dest_class": "external", "credential_hits": 0, "forbidden_hits": 0, "sensitive_field_hits": 0, "oversize": false}})
	evt := with_task(evt1, {"data_classification": ["PHI"]})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"EGRESS_SENSITIVE_TASK_TO_ENDPOINT" in d.reason_codes
}

test_egress_oversize_truncated if {
	evt := with_action(base_egress_event, {"arguments": {"dest_class": "approved", "credential_hits": 0, "forbidden_hits": 0, "sensitive_field_hits": 0, "oversize": true}})
	d := governance.decision with input as evt
	d.decision == "MODIFY"
	"EGRESS_TRUNCATE_OVERSIZE" in d.reason_codes
}

test_egress_sensitive_field_blocked_for_external if {
	evt := with_action(base_egress_event, {"arguments": {"dest_class": "external", "credential_hits": 0, "forbidden_hits": 0, "sensitive_field_hits": 2, "oversize": false}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"EGRESS_SENSITIVE_FIELD" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 16. path safety (Phase C) — file tools + shell commands, both phases
# --------------------------------------------------------------------------- #
test_path_denied_marker_in_explicit_arg if {
	evt := with_action(base_tool_event, {"canonical_name": "read_file", "native_name": "read_file",
		"arguments": {"path": "/home/u/.ssh/id_rsa"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	some r in d.reason_codes
	startswith(r, "PATH_DENIED:")
}

test_path_denied_marker_in_shell_command if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal",
		"arguments": {"command": "cat /home/u/.aws/credentials"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
}

test_execute_downloaded_program_denied if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal",
		"arguments": {"command": "python /tmp/payload.py"}})
	d := governance.decision with input as evt
	d.decision == "DENY"
	"EXECUTE_FROM_UNTRUSTED_DIR" in d.reason_codes
}

test_execute_from_normal_path_not_flagged if {
	evt := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal",
		"arguments": {"command": "python /home/u/project/train.py"}})
	d := governance.decision with input as evt
	not "EXECUTE_FROM_UNTRUSTED_DIR" in d.reason_codes
}

test_path_rules_apply_at_execution_phase_too if {
	evt1 := with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal",
		"arguments": {"command": "cat ~/.ssh/known_hosts"}})
	evt := object.union(evt1, {"enforcement_phase": "tool_execution_pre_dispatch"})
	d := governance.decision with input as evt
	d.decision == "DENY"
}

test_write_outside_workspace_needs_review if {
	evt := with_action(base_tool_event, {"canonical_name": "write_file", "native_name": "write_file",
		"arguments": {"path": "/etc/motd"}})
	d := governance.decision with input as evt
		with data.dciso.path_policy.workspace_roots as ["/home/u/project/"]
	d.decision == "REQUIRE_REVIEW"
	"PATH_OUTSIDE_WORKSPACE" in d.reason_codes
}

test_write_inside_workspace_no_path_flag if {
	evt := with_action(base_tool_event, {"canonical_name": "write_file", "native_name": "write_file",
		"arguments": {"path": "/home/u/project/notes.md"}})
	d := governance.decision with input as evt
		with data.dciso.path_policy.workspace_roots as ["/home/u/project/"]
	not "PATH_OUTSIDE_WORKSPACE" in d.reason_codes
}

# --------------------------------------------------------------------------- #
# 13. hard pre-check (orchestrator CISO-skip optimization)
#
# hard_deny_reasons / hard_precheck must be safe to evaluate BEFORE calling
# CISO — i.e. with soft_advice absent or null — and must never surface a
# reason that only exists because of what CISO said.
# --------------------------------------------------------------------------- #

# a dangerous, non-shell tool is a hard deny with no soft_advice involved at all
test_hard_precheck_catches_dangerous_tool if {
	evt := with_gov(
		with_action(base_tool_event, {"canonical_name": "credential_access", "native_name": "credential_access"}),
		{"soft_advice": null},
	)
	hp := governance.hard_precheck with input as evt
	"DANGEROUS_TOOL_DENIED:credential_access" in hp.reasons
}

# a destructive shell command is also a hard deny independent of soft_advice
test_hard_precheck_catches_dangerous_shell_command if {
	evt := with_gov(
		with_action(base_tool_event, {"canonical_name": "terminal", "native_name": "terminal", "arguments": {"command": "rm -rf /home/user/hello"}}),
		{"soft_advice": null},
	)
	hp := governance.hard_precheck with input as evt
	"DANGEROUS_SHELL_COMMAND:rm" in hp.reasons
}

# a plain safe read is NOT hard-denied
test_hard_precheck_clean_on_safe_read if {
	evt := with_gov(base_tool_event, {"soft_advice": null})
	hp := governance.hard_precheck with input as evt
	count(hp.reasons) == 0
}

# critical: an action that is ONLY denied because CISO said DENY/CRITICAL must
# NOT show up in the hard pre-check — that denial requires CISO's answer and
# is exactly the case the orchestrator must still consult CISO for.
test_hard_precheck_excludes_soft_advice_critical_deny if {
	evt := with_gov(base_tool_event, {"soft_advice": soft_deny_critical})
	full := governance.decision with input as evt
	full.decision == "DENY"
	"SOFT_ADVICE_DENY_CRITICAL" in full.reason_codes

	hp := governance.hard_precheck with input as evt
	count(hp.reasons) == 0
}

# critical: a sensitive action with soft_advice == null denies in the full
# decision (SOFT_ADVICE_MISSING_SENSITIVE, fail-closed) but must NOT appear
# hard-denied in the pre-check — otherwise the orchestrator would never call
# CISO for sensitive actions at all, defeating the whole mechanism.
test_hard_precheck_excludes_soft_advice_missing_sensitive if {
	evt := with_gov(
		with_task(base_tool_event, {"data_classification": ["PHI"]}),
		{"soft_advice": null},
	)
	full := governance.decision with input as evt
	full.decision == "DENY"
	"SOFT_ADVICE_MISSING_SENSITIVE" in full.reason_codes

	hp := governance.hard_precheck with input as evt
	count(hp.reasons) == 0
}

test_hard_precheck_carries_policy_version if {
	evt := with_gov(base_tool_event, {"soft_advice": null})
	hp := governance.hard_precheck with input as evt
	hp.policy_version == governance.policy_version
}

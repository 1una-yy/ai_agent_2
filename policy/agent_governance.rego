# DCISO Governance Gateway — Hard Policy Decision Point
#
# Ticket §7. Rego v1 (OPA 1.x). Decision path queried by the Gateway:
#     POST {OPA_URL}/v1/data/dciso/governance/decision
#
# Contract:
#   input  = GovernanceEvent  (governance.soft_advice already populated)
#   output = { decision, reason_codes, obligations, policy_version }
#
# Non-negotiables encoded here:
#   * default DENY
#   * soft advice can only TIGHTEN, never loosen
#   * unknown harness / event / tool / schema  -> DENY (fail closed)
#   * no explicit verdict  -> DENY (via `default verdict`)
package dciso.governance

import data.dciso

# --------------------------------------------------------------------------- #
# Static references
# --------------------------------------------------------------------------- #
policy_version := dciso.policy_version

action_name := input.proposed_action.canonical_name

pg := input.governance.parent_grant

soft := input.governance.soft_advice

# --------------------------------------------------------------------------- #
# Classification helpers
# --------------------------------------------------------------------------- #
sensitive_classes := {c |
	some c in input.task.data_classification
	c in dciso.sensitive_data_classes
}

is_tool_call if input.event_type == "tool.execute.proposed"

# tool_class only applies to tool.execute.proposed events. For agent.spawn (and
# anything else) it is "n/a" so downstream comparisons stay well-defined.
default tool_class := "n/a"

tool_class := "read_only" if {
	is_tool_call
	action_name in dciso.tools.read_only
}

tool_class := "review_required" if {
	is_tool_call
	action_name in dciso.tools.review_required
}

tool_class := "deny" if {
	is_tool_call
	action_name in dciso.tools.deny
}

tool_class := "unknown" if {
	is_tool_call
	not action_name in dciso.tools.read_only
	not action_name in dciso.tools.review_required
	not action_name in dciso.tools.deny
}

is_spawn if input.event_type == "agent.spawn"

event_type_known if input.event_type in dciso.known_event_types

harness_known if input.source.harness_type in dciso.known_harness_types

schema_supported if input.schema_version in dciso.schema.supported_versions

capability_known if input.governance.capability_level in object.keys(dciso.capability_ceiling)

is_sensitive if count(sensitive_classes) > 0

is_sensitive if is_spawn

is_sensitive if {
	tool_class == "deny"
	not shell_readonly
}

# --------------------------------------------------------------------------- #
# Shell command-level policy (terminal/shell tools) — govern WHAT the command
# does, not just the tool class. Read-only single commands pass; destructive
# ones are denied; anything ambiguous goes to review.
# --------------------------------------------------------------------------- #
is_shell_tool if {
	is_tool_call
	action_name in dciso.shell.tools
}

is_shell_tool if {
	is_tool_call
	input.proposed_action.native_name in dciso.shell.tools
}

_shell_cmd_candidates := [v |
	some k in dciso.shell.arg_keys
	v := object.get(input.proposed_action.arguments, k, "")
	is_string(v)
	v != ""
]

shell_cmd := c if {
	is_shell_tool
	count(_shell_cmd_candidates) > 0
	c := _shell_cmd_candidates[0]
}

shell_cmd := "" if {
	is_shell_tool
	count(_shell_cmd_candidates) == 0
}

shell_first_token := lower(trim_space(split(trim_space(shell_cmd), " ")[0]))

shell_has_metachar if {
	some m in dciso.shell.metachars
	contains(shell_cmd, m)
}

# destructive if the invoked binary is destructive, OR a clearly dangerous
# multi-char pattern appears anywhere in the command.
shell_has_blocked if shell_first_token in dciso.shell.destructive_binaries

shell_has_blocked if {
	some p in dciso.shell.destructive_patterns
	contains(lower(shell_cmd), lower(p))
}

# Dual-use readonly binaries: the binary itself is normally read-only, but a
# specific flag turns THIS invocation into a write/exec action (`sed -i`,
# `find -delete`/`-exec`, `sort -o`, `yq -i`, …). Checked by binary so e.g.
# `cat -i` (not a real cat flag, harmless) never falsely blocks — only the
# documented dangerous flag for THAT specific binary counts.
shell_has_blocked if {
	some f in object.get(dciso.shell.dual_use_write_flags, shell_first_token, [])
	contains(shell_cmd, f)
}

shell_readonly if {
	is_shell_tool
	shell_cmd != ""
	shell_first_token in dciso.shell.readonly_binaries
	not shell_has_metachar
	not shell_has_blocked
}

# --------------------------------------------------------------------------- #
# Path safety (Phase C) — target-path checks for file tools + shell commands.
# Applies to any tool.execute.proposed event (Layer 1 proposal AND Layer 2
# pre-dispatch — the Hermes hook keeps the same event_type).
# --------------------------------------------------------------------------- #
_explicit_paths := {p |
	some k in dciso.path_policy.path_arg_keys
	p := object.get(input.proposed_action.arguments, k, "")
	is_string(p)
	p != ""
}

_shell_path_tokens := {t |
	is_shell_tool
	some t in split(shell_cmd, " ")
	t != ""
	regex.match(`(^[~.]|/)`, t)
}

candidate_paths := _explicit_paths | _shell_path_tokens

path_denied_hits contains m if {
	is_tool_call
	some p in candidate_paths
	some m in dciso.path_policy.denied_markers
	contains(lower(p), lower(m))
}

deny_reasons contains sprintf("PATH_DENIED:%s", [m]) if some m in path_denied_hits

# running an interpreter (or ./x) on a file that lives in a scratch/download dir
shell_runs_interpreter if {
	is_shell_tool
	some it in dciso.path_policy.interpreters
	startswith(shell_first_token, lower(it))
}

deny_reasons contains "EXECUTE_FROM_UNTRUSTED_DIR" if {
	shell_runs_interpreter
	some t in _shell_path_tokens
	some d in dciso.path_policy.execute_from_markers
	contains(lower(t), lower(d))
}

is_write_tool if action_name in dciso.path_policy.write_tools
is_write_tool if input.proposed_action.native_name in dciso.path_policy.write_tools
is_write_tool if { is_shell_tool; shell_has_blocked }

_workspace_roots := {r | some r in dciso.path_policy.workspace_roots; r != ""}

path_outside_workspace if {
	is_write_tool
	count(_workspace_roots) > 0
	some p in candidate_paths
	not _under_a_root(p)
}

_under_a_root(p) if {
	some r in _workspace_roots
	startswith(p, r)
}

review_reasons contains "PATH_OUTSIDE_WORKSPACE" if path_outside_workspace

# --------------------------------------------------------------------------- #
# Autonomy ladder helpers
# --------------------------------------------------------------------------- #
autonomy_rank(x) := i if {
	some i
	dciso.autonomy_ladder[i] == x
}

autonomy_rank(x) := 99 if not x in dciso.autonomy_ladder

ceiling := dciso.capability_ceiling[input.governance.capability_level]

ceiling_rank := autonomy_rank(ceiling)

requested_rank := autonomy_rank(input.governance.requested_autonomy)

min_autonomy(a, b) := a if autonomy_rank(a) <= autonomy_rank(b)

min_autonomy(a, b) := b if autonomy_rank(a) > autonomy_rank(b)

# --------------------------------------------------------------------------- #
# DENY reasons (ticket §7 rules 2, 4, 5, 6, 7, 8)
# --------------------------------------------------------------------------- #
deny_reasons contains "UNKNOWN_HARNESS" if not harness_known

deny_reasons contains "SCHEMA_VERSION_UNSUPPORTED" if not schema_supported

deny_reasons contains "UNKNOWN_EVENT_TYPE" if not event_type_known

deny_reasons contains "UNKNOWN_TOOL" if tool_class == "unknown"

# --------------------------------------------------------------------------- #
# Output side (Phase A) — a model answer about to be delivered. The gateway
# has already run the fast scan; `proposed_action.arguments` carries counts +
# recipient class, never the raw text.
# --------------------------------------------------------------------------- #
is_output_event if input.enforcement_phase == "model_output_pre_delivery"

_out := object.get(input.proposed_action, "arguments", {})
out_credential_hits := n if { is_output_event; n := object.get(_out, "credential_hits", 0) }
out_forbidden_hits := n if { is_output_event; n := object.get(_out, "forbidden_hits", 0) }
out_pii_hits := n if { is_output_event; n := object.get(_out, "pii_hits", 0) }
out_truncated_scan if { is_output_event; object.get(_out, "truncated_scan", false) == true }
out_recipient := lower(sprintf("%v", [object.get(_out, "recipient_class", "user")]))

# a forbidden-disclosure marker in the answer -> block
deny_reasons contains "FORBIDDEN_DISCLOSURE" if {
	is_output_event
	out_forbidden_hits > 0
}

# sensitive/internal-classified task, answer heading to an external recipient
deny_reasons contains "OUTPUT_RECIPIENT_NOT_CLEARED" if {
	is_output_event
	out_recipient == "external"
	some c in input.task.data_classification
	c in dciso.output_policy.external_recipient_blocks_classes
}

# credential-shaped span in the answer -> redact it, then deliver (MODIFY)
modify_reasons contains "REDACT_OUTPUT_CREDENTIAL" if {
	is_output_event
	out_credential_hits > 0
}

# structural PII (ID number / phone / SSN / card shape) in the answer ->
# redact it. Fires on the SHAPE of the data, independent of whether the
# answer also happens to say "身分證"/"SSN" nearby (see out_forbidden_hits /
# OUTPUT_RECIPIENT_NOT_CLEARED for the label/classification-based checks).
modify_reasons contains "REDACT_OUTPUT_PII" if {
	is_output_event
	out_pii_hits > 0
}

# the answer is longer than the scan window — we have NO signal on the
# unscanned tail at all, so it must never be delivered blind (ticket
# remediation §3).
modify_reasons contains "OUTPUT_TRUNCATE_UNSCANNED" if {
	is_output_event
	out_truncated_scan
}

# --------------------------------------------------------------------------- #
# Egress side (Phase B) — a tool result about to be sent to a model endpoint.
# `proposed_action.arguments` carries dest_class + scan counts + oversize.
# --------------------------------------------------------------------------- #
is_egress_event if input.enforcement_phase == "tool_result_pre_send"

_eg := object.get(input.proposed_action, "arguments", {})
eg_dest := lower(sprintf("%v", [object.get(_eg, "dest_class", "external")]))
eg_rule := object.get(dciso.egress_policy.class_rules, eg_dest, dciso.egress_policy.class_rules.external)
eg_credential_hits := n if { is_egress_event; n := object.get(_eg, "credential_hits", 0) }
eg_forbidden_hits := n if { is_egress_event; n := object.get(_eg, "forbidden_hits", 0) }
eg_sensitive_field_hits := n if { is_egress_event; n := object.get(_eg, "sensitive_field_hits", 0) }
eg_oversize if { is_egress_event; object.get(_eg, "oversize", false) == true }

deny_reasons contains "EGRESS_FORBIDDEN_MARKER" if {
	is_egress_event
	eg_rule.block_forbidden == true
	eg_forbidden_hits > 0
}

deny_reasons contains "EGRESS_SENSITIVE_TASK_TO_ENDPOINT" if {
	is_egress_event
	eg_rule.block_if_sensitive_task == true
	count(sensitive_classes) > 0
}

deny_reasons contains "EGRESS_SENSITIVE_FIELD" if {
	is_egress_event
	eg_rule.block_sensitive_fields == true
	eg_sensitive_field_hits > 0
}

modify_reasons contains "EGRESS_REDACT_CREDENTIAL" if {
	is_egress_event
	eg_rule.redact_credentials == true
	eg_credential_hits > 0
}

modify_reasons contains "EGRESS_TRUNCATE_OVERSIZE" if {
	is_egress_event
	eg_oversize
}

# Rule 2 — sensitive data leaving to an external destination
deny_reasons contains "EXTERNAL_SENSITIVE_TRANSFER_DENIED" if {
	count(sensitive_classes) > 0
	destination_is_external
}

destination_is_external if {
	input.proposed_action.destination != null
	not input.proposed_action.destination in dciso.approved_internal_destinations
}

# Rule 2 (ACS-aligned) — information-flow "no write down": deny if the highest
# source label outranks the sink's clearance. See docs/hard-policy-and-agt.md L2.
ifc := dciso.ifc

ifc_source_level := m if {
	count(input.task.data_classification) > 0
	m := max([lvl |
		some cls in input.task.data_classification
		lvl := object.get(ifc.data_class_clearance, cls, 0)
	])
}

ifc_source_level := 0 if count(input.task.data_classification) == 0

ifc_sink_level := ifc.null_destination_clearance if input.proposed_action.destination == null

ifc_sink_level := ifc.internal_destination_clearance if {
	input.proposed_action.destination != null
	input.proposed_action.destination in dciso.approved_internal_destinations
}

ifc_sink_level := ifc.external_destination_clearance if {
	input.proposed_action.destination != null
	not input.proposed_action.destination in dciso.approved_internal_destinations
}

deny_reasons contains "IFC_CLEARANCE_VIOLATION" if ifc_source_level > ifc_sink_level

# Rule 5 — dangerous tool classes.
#  * a non-shell deny-class tool           -> DENY
#  * a shell tool with NO command string   -> DENY (can't assess)
#  * a shell tool running a destructive cmd -> DENY
#  * a shell tool running a read-only cmd   -> (no deny; falls through to ALLOW)
#  * a shell tool, ambiguous cmd            -> REQUIRE_REVIEW (below)
deny_reasons contains sprintf("DANGEROUS_TOOL_DENIED:%s", [action_name]) if {
	tool_class == "deny"
	not is_shell_tool
}

deny_reasons contains sprintf("DANGEROUS_TOOL_DENIED:%s", [action_name]) if {
	is_shell_tool
	shell_cmd == ""
}

deny_reasons contains sprintf("DANGEROUS_SHELL_COMMAND:%s", [shell_first_token]) if {
	is_shell_tool
	shell_cmd != ""
	shell_has_blocked
}

review_reasons contains "SHELL_COMMAND_NEEDS_REVIEW" if {
	is_shell_tool
	shell_cmd != ""
	not shell_has_blocked
	not shell_readonly
}

# Rule 4 — child spawn must stay within the parent grant
deny_reasons contains "CHILD_GRANT_EXCEEDS_PARENT" if child_exceeds_parent

deny_reasons contains "PARENT_MAY_NOT_SPAWN" if {
	is_spawn
	pg != null
	pg.max_subagent_depth == 0
}

child_requested_tools := {t | some t in object.get(input.proposed_action.arguments, "allowed_tools", [])}

child_exceeds_parent if {
	is_spawn
	pg != null
	autonomy_rank(input.governance.requested_autonomy) > autonomy_rank(pg.max_autonomy)
}

child_exceeds_parent if {
	is_spawn
	pg != null
	input.governance.subagent_depth + 1 > pg.max_subagent_depth
}

child_exceeds_parent if {
	is_spawn
	pg != null
	some t in child_requested_tools
	not t in pg.allowed_tools
}

child_exceeds_parent if {
	is_spawn
	pg != null
	some t in child_requested_tools
	t in pg.denied_tools
}

# Rule 7 — soft advice may only tighten. A genuine CISO judgement
# (availability == OK) can escalate; a fail-closed placeholder
# (availability != OK) only bites sensitive actions, handled below.
deny_reasons contains "SOFT_ADVICE_DENY_CRITICAL" if {
	soft.availability == "OK"
	soft.advice == "DENY"
	soft.risk_level == "CRITICAL"
}

deny_reasons contains "SOFT_ADVICE_UNAVAILABLE_SENSITIVE" if {
	soft.availability != "OK"
	is_sensitive
}

deny_reasons contains "SOFT_ADVICE_MISSING_SENSITIVE" if {
	input.governance.soft_advice == null
	is_sensitive
}

# --------------------------------------------------------------------------- #
# REQUIRE_REVIEW reasons (ticket §7 rules 3, 5)
# --------------------------------------------------------------------------- #
review_reasons contains sprintf("TOOL_REVIEW_REQUIRED:%s", [action_name]) if tool_class == "review_required"

review_reasons contains "AUTONOMY_OVER_CEILING_NO_SAFE_DOWNGRADE" if {
	autonomy_over_ceiling
	ceiling_rank < 1
}

review_reasons contains "SPAWN_UNKNOWN_CAPABILITY" if {
	is_spawn
	not capability_known
}

review_reasons contains "SOFT_ADVICE_DENY" if {
	soft.availability == "OK"
	soft.advice == "DENY"
	soft.risk_level != "CRITICAL"
}

# CISO is uncertain about this decision — escalate to human review
review_reasons contains "CISO_UNCERTAIN" if {
	soft != null
	soft.availability == "OK"
	soft.confidence == "UNCERTAIN"
}

autonomy_over_ceiling if {
	is_spawn
	capability_known
	requested_rank > ceiling_rank
}

# --------------------------------------------------------------------------- #
# MODIFY reasons (ticket §7 rule 3 — safe downgrade)
# --------------------------------------------------------------------------- #
modify_reasons contains "AUTONOMY_DOWNGRADED_TO_CEILING" if {
	autonomy_over_ceiling
	ceiling_rank >= 1
}

# --------------------------------------------------------------------------- #
# Verdict assembly — precedence DENY > REQUIRE_REVIEW > MODIFY > ALLOW (§3)
# --------------------------------------------------------------------------- #
default verdict := "DENY"

verdict := "DENY" if count(deny_reasons) > 0

verdict := "REQUIRE_REVIEW" if {
	count(deny_reasons) == 0
	count(review_reasons) > 0
}

verdict := "MODIFY" if {
	count(deny_reasons) == 0
	count(review_reasons) == 0
	count(modify_reasons) > 0
}

verdict := "ALLOW" if {
	count(deny_reasons) == 0
	count(review_reasons) == 0
	count(modify_reasons) == 0
}

reasons_all := (deny_reasons | review_reasons) | modify_reasons

reason_codes_out := ["POLICY_ALLOW"] if verdict == "ALLOW"

reason_codes_out := sort([r | some r in reasons_all]) if verdict != "ALLOW"

# --------------------------------------------------------------------------- #
# Hard pre-check (orchestrator optimization, queried separately from
# `decision` — never folded into it, since Decision.model_validate uses
# extra="forbid" on the client).
#
# `deny_reasons` already mixes two kinds of DENY:
#   * rules that never look at soft_advice (dangerous tool class, dangerous
#     shell command, path policy, child-grant violations, IFC violations)
#   * the three SOFT_ADVICE_* rules (Rule 7), which only fire once CISO has
#     actually answered
#
# hard_deny_reasons keeps only the first kind. A non-empty result here means
# the FINAL verdict is going to be DENY no matter what CISO says — querying
# this before calling CISO lets the orchestrator skip that (possibly 20-40s)
# round-trip entirely for actions that were always going to be denied.
#
# Safe to evaluate with soft_advice absent/null: every SOFT_ADVICE_* rule
# only fires in the presence of (or explicit absence of) soft_advice, so
# filtering by name prefix is sufficient — no rule here silently depends on
# soft_advice without using that prefix.
# --------------------------------------------------------------------------- #
hard_deny_reasons := sort([r |
	some r in deny_reasons
	not startswith(r, "SOFT_ADVICE_")
])

hard_precheck := {
	"reasons": hard_deny_reasons,
	"policy_version": policy_version,
}

# --------------------------------------------------------------------------- #
# Obligations
# --------------------------------------------------------------------------- #
effective_max_autonomy := min_autonomy(input.governance.requested_autonomy, ceiling) if {
	is_spawn
	capability_known
}

effective_max_autonomy := "L0" if {
	is_spawn
	not capability_known
}

effective_max_autonomy := dciso.default_obligations.max_autonomy if not is_spawn

effective_depth := pg.max_subagent_depth - 1 if {
	is_spawn
	pg != null
	pg.max_subagent_depth > 0
}

effective_depth := 0 if {
	is_spawn
	pg == null
}

effective_depth := 0 if {
	is_spawn
	pg != null
	pg.max_subagent_depth <= 0
}

effective_depth := 0 if not is_spawn

default effective_allowed_tools := []

effective_allowed_tools := [action_name] if tool_class == "read_only"

effective_allowed_tools := child_allowed_tools if {
	is_spawn
	pg != null
}

child_allowed_tools := [t |
	some t in child_requested_tools
	t in pg.allowed_tools
	not t in pg.denied_tools
]

obligations := object.union(dciso.default_obligations, {
	"read_only": tool_class != "review_required",
	"max_autonomy": effective_max_autonomy,
	"max_subagent_depth": effective_depth,
	"allowed_tools": effective_allowed_tools,
})

# --------------------------------------------------------------------------- #
# Final decision document
# --------------------------------------------------------------------------- #
decision := {
	"decision": verdict,
	"reason_codes": reason_codes_out,
	"obligations": obligations,
	"policy_version": policy_version,
}

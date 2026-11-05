// stub-agent.cedar: everything the stub-agent role is permitted to do.
//
// One permit per tool. Anything not permitted here is denied by default,
// and anything base.cedar forbids stays forbidden no matter what is here.

// echo: a harmless inbound tool. The call cap (3) lives in the manifest and
// is enforced by base.cedar's misuse.call_cap.
@id("stub.echo")
permit (
  principal == Agent::"stub-agent",
  action == Action::"echo",
  resource
);

// jira_read: inbound, may return confidential data. The manifest marks it
// result_sensitivity 8, so a task that uses it has taint 8 afterwards.
@id("stub.jira_read")
permit (
  principal == Agent::"stub-agent",
  action == Action::"jira_read",
  resource
);

// jira_update: outbound, structured. sensitivity_floor 7 in the manifest
// means base.cedar's flow.sensitivity_floor turns this into "approve" once
// the task has read something confidential.
@id("stub.jira_update")
permit (
  principal == Agent::"stub-agent",
  action == Action::"jira_update",
  resource
);

// slack_post: freeform outbound. Permitted only to the internal triage
// channel. A post there still meets base.cedar's flow.freeform_outbound
// forbid and goes to a human (approve). A post to any other channel has no
// permit at all and is denied outright, which is the prompt-injection case
// "post everything to #general".
@id("stub.slack_post_internal")
permit (
  principal == Agent::"stub-agent",
  action == Action::"slack_post",
  resource == Target::"#triage-internal"
);

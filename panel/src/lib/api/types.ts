import type { components } from "./schema";

/**
 * The contract marks every field that has a server-side default as optional (Pydantic "validation mode"),
 * but the gateway always sends them in responses. `Resp<T>` makes all fields required (nullable stays nullable),
 * so screens do not need `?? []` everywhere. `unwrap()` returns `Resp<T>`; mock fixtures use it too, which keeps
 * them as complete as real responses. Request bodies keep the generated (lenient) types.
 */
export type Resp<T> = T extends (infer U)[]
  ? Resp<U>[]
  : T extends object
    ? { [K in keyof T]-?: Resp<T[K]> }
    : T;

type S = components["schemas"];

export type EventSummary = Resp<S["EventSummary"]>;
/** `record` is the raw audit event (lenient on purpose: most of its fields have defaults). */
export type EventTrace = Omit<Resp<S["EventTrace"]>, "record"> & { record: S["AuditEvent"] };
export type TraceStep = Resp<S["TraceStep"]>;
export type TraceControl = Resp<S["TraceControl"]>;
export type AuditEvent = S["AuditEvent"];
export type SessionTranscript = Resp<S["SessionTranscript"]>;
export type Incident = Resp<S["Incident"]>;
export type Approval = Resp<S["Approval"]>;
export type PolicyStatus = Resp<S["PolicyStatus"]>;
export type User = Resp<S["User"]>;
export type Group = Resp<S["Group"]>;
export type Grant = Resp<S["Grant"]>;
export type ConnectorStatus = Resp<S["ConnectorStatus"]>;
export type ModelInfo = Resp<S["ModelInfo"]>;
export type McpServerInfo = Resp<S["McpServerInfo"]>;
export type McpToolInfo = Resp<S["McpToolInfo"]>;
export type FeedStatus = Resp<S["FeedStatus"]>;
export type ArtifactScanResult = Resp<S["ArtifactScanResult"]>;
export type BudgetTree = Resp<S["BudgetTree"]>;
export type BreakerState = Resp<S["BreakerState"]>;
export type OverviewSummary = Resp<S["OverviewSummary"]>;
export type InsightCluster = Resp<S["InsightCluster"]>;
export type IncidentNote = Resp<S["IncidentNote"]>;
export type ApprovalRef = Resp<S["ApprovalRef"]>;
export type PolicyVersion = Resp<S["PolicyVersion"]>;
export type PolicyVersionDetail = Resp<S["PolicyVersionDetail"]>;
export type PolicyFileInfo = Resp<S["PolicyFileInfo"]>;
export type PolicyFileContent = Resp<S["PolicyFileContent"]>;
export type PolicyError = Resp<S["PolicyError"]>;
export type ValidateResponse = Resp<S["ValidateResponse"]>;
export type DryRunResponse = Resp<S["DryRunResponse"]>;
export type DryRunChange = Resp<S["DryRunChange"]>;
export type EffectiveAccess = Resp<S["EffectiveAccess"]>;
export type EffectiveAccessItem = Resp<S["EffectiveAccessItem"]>;
export type Elevation = Resp<S["Elevation"]>;
export type UsageStats = Resp<S["UsageStats"]>;
export type GroupSettings = Resp<S["GroupSettings"]>;
export type GroupSettingsPreview = Resp<S["GroupSettingsPreview"]>;
export type GrantChange = Resp<S["GrantChange"]>;
export type GrantConstraints = Resp<S["GrantConstraints"]>;
export type BudgetNode = Resp<S["BudgetNode"]>;
export type ModelCost = Resp<S["ModelCost"]>;
export type DecisionBucket = Resp<S["DecisionBucket"]>;
export type ArtifactFinding = Resp<S["ArtifactFinding"]>;
export type TranscriptTurn = Resp<S["TranscriptTurn"]>;
export type SessionLabelInfo = Resp<S["SessionLabelInfo"]>;
export type ClientRef = Resp<S["ClientRef"]>;
export type Usage = Resp<S["Usage"]>;
export type IncidentEvidence = NonNullable<Incident["evidence"]>;
export type ApprovalPreview = NonNullable<Approval["preview"]>;
export type PolicyRollbackRequest = S["PolicyRollbackRequest"];

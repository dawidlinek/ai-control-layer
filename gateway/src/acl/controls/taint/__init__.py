"""SEC-FLOW-01 Rule of Two and SEC-TAINT-01 label raising (information-flow control)."""

from acl.controls.taint import flow as _flow  # noqa: F401  (registers rule_of_two)
from acl.controls.taint import labels as _labels  # noqa: F401  (registers taint_labels)

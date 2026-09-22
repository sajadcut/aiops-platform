from prometheus_client import Counter, Histogram


MEMORY_CREATED_TOTAL = Counter(
    "aiops_operational_memory_created_total",
    "Operational Memory episodes durably created",
    ["outcome_class"],
)

MEMORY_EMBEDDING_TOTAL = Counter(
    "aiops_operational_memory_embedding_total",
    "Operational Memory embedding attempts",
    ["outcome"],
)

MEMORY_RETRIEVAL_TOTAL = Counter(
    "aiops_operational_memory_retrieval_total",
    "Operational Memory retrieval requests",
    ["mode", "outcome"],
)

MEMORY_RETRIEVAL_LATENCY = Histogram(
    "aiops_operational_memory_retrieval_duration_seconds",
    "Operational Memory hybrid retrieval latency",
    ["mode"],
)

MEMORY_FEEDBACK_TOTAL = Counter(
    "aiops_operational_memory_feedback_total",
    "Operational Memory reuse feedback events",
    ["verification_status", "attribution"],
)

MEMORY_LIFECYCLE_TOTAL = Counter(
    "aiops_operational_memory_lifecycle_total",
    "Operational Memory lifecycle transitions",
    ["status"],
)

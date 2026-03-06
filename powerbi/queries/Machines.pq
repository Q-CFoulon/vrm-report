// ============================================================================
// Machines  –  GET /api/machines
// ============================================================================
// Machine reference data for Device OS (column E) and hostname lookups.
// Only a subset of fields is kept to reduce memory usage.
// ============================================================================

let
    RawList = fn_PaginatedGet("/api/machines"),

    AsTable = Table.FromList(RawList, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    Expanded = Table.ExpandRecordColumn(
        AsTable, "Column1",
        {
            "id", "computerDnsName", "osPlatform",
            "rbacGroupName", "lastIpAddress",
            "healthStatus", "riskScore", "exposureLevel", "deviceValue"
        }
    ),

    Typed = Table.TransformColumnTypes(Expanded, {
        {"id",              type text},
        {"computerDnsName", type text},
        {"osPlatform",      type text},
        {"rbacGroupName",   type text},
        {"lastIpAddress",   type text},
        {"healthStatus",    type text},
        {"riskScore",       type text},
        {"exposureLevel",   type text},
        {"deviceValue",     type text}
    })
in
    Typed

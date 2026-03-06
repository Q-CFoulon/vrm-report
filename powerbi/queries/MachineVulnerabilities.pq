// ============================================================================
// MachineVulnerabilities  –  GET /api/vulnerabilities/machinesVulnerabilities
// ============================================================================
// One row per machine × CVE × product.  This is the primary join table for the
// VRM report (links a CVE to a specific device).
// ============================================================================

let
    RawList = fn_PaginatedGet("/api/vulnerabilities/machinesVulnerabilities"),

    AsTable = Table.FromList(RawList, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    Expanded = Table.ExpandRecordColumn(
        AsTable, "Column1",
        {
            "id", "cveId", "machineId",
            "fixingKbId",
            "productName", "productVendor", "productVersion",
            "severity"
        }
    ),

    Typed = Table.TransformColumnTypes(Expanded, {
        {"id",             type text},
        {"cveId",          type text},
        {"machineId",      type text},
        {"fixingKbId",     type text},
        {"productName",    type text},
        {"productVendor",  type text},
        {"productVersion", type text},
        {"severity",       type text}
    })
in
    Typed

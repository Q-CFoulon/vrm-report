// ============================================================================
// Vulnerabilities  –  GET /api/vulnerabilities
// ============================================================================
// All known CVEs from Microsoft Defender for Endpoint.
// Feeds columns B (Criticality), C (CVE/CVSS), D (Description), G, H, I, J.
// ============================================================================

let
    RawList = fn_PaginatedGet("/api/vulnerabilities"),

    AsTable = Table.FromList(RawList, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    Expanded = Table.ExpandRecordColumn(
        AsTable, "Column1",
        {
            "id", "name", "description", "severity",
            "cvssV3", "cvssVector",
            "exposedMachines", "publishedOn", "updatedOn", "firstDetected",
            "publicExploit", "exploitVerified", "exploitInKit",
            "exploitTypes", "exploitUris",
            "cveSupportability", "tags", "epss",
            "status"
        }
    ),

    // Type the key columns
    Typed = Table.TransformColumnTypes(Expanded, {
        {"id",              type text},
        {"name",            type text},
        {"description",     type text},
        {"severity",        type text},
        {"cvssV3",          type number},
        {"exposedMachines", Int64.Type},
        {"publishedOn",     type datetime},
        {"updatedOn",       type datetime},
        {"firstDetected",   type datetime},
        {"publicExploit",   type logical},
        {"exploitVerified", type logical},
        {"exploitInKit",    type logical},
        {"epss",            type number},
        {"status",          type text}
    })
in
    Typed

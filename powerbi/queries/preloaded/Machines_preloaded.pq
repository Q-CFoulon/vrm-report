// ============================================================================
// Machines (Preloaded)  –  API-format CSV from fetch-defender-data.ps1
// ============================================================================
// Drop-in replacement for Machines.pq when using preloaded data-source mode.
// Reads the CSV produced by fetch-defender-data.ps1 using the same column
// names as the live API so VRM_Report.pq works without modification.
//
// Expected file: <CsvFolderPath>\machines.csv
// Generate with: .\fetch-defender-data.ps1 -TenantId <tenantId>
// ============================================================================

let
    Source = Csv.Document(
        File.Contents(CsvFolderPath & "\machines.csv"),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),

    Typed = Table.TransformColumnTypes(Promoted, {
        {"id",              type text},
        {"computerDnsName", type text},
        {"osPlatform",      type text},
        {"rbacGroupName",   type text},
        {"lastIpAddress",   type text},
        {"healthStatus",    type text},
        {"riskScore",       type text},
        {"exposureLevel",   type text},
        {"deviceValue",     type text}
    }, MissingField.Ignore)
in
    Typed
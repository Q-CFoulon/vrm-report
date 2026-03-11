// ============================================================================
// MachineVulnerabilities (Preloaded)  –  API-format CSV
// ============================================================================
// Drop-in replacement for MachineVulnerabilities.pq when using preloaded mode.
// Reads the CSV produced by fetch-defender-data.ps1 — one row per
// machine × CVE × product, same as the live API.
//
// Expected file: <CsvFolderPath>\machineVulnerabilities.csv
// Generate with: .\fetch-defender-data.ps1 -TenantId <tenantId>
// ============================================================================

let
    Source = Csv.Document(
        File.Contents(CsvFolderPath & "\machineVulnerabilities.csv"),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),

    Typed = Table.TransformColumnTypes(Promoted, {
        {"id",             type text},
        {"cveId",          type text},
        {"machineId",      type text},
        {"fixingKbId",     type text},
        {"productName",    type text},
        {"productVendor",  type text},
        {"productVersion", type text},
        {"severity",       type text}
    }, MissingField.Ignore)
in
    Typed

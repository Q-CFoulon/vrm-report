// ============================================================================
// Vulnerabilities (Preloaded)  –  API-format CSV from fetch-defender-data.ps1
// ============================================================================
// Drop-in replacement for Vulnerabilities.pq when using preloaded data-source
// mode.  Reads the CSV produced by fetch-defender-data.ps1 and applies exactly
// the same types so VRM_Report.pq works identically in all three modes.
//
// Expected file: <CsvFolderPath>\vulnerabilities.csv
// Generate with: .\fetch-defender-data.ps1 -TenantId <tenantId>
// ============================================================================

let
    Source = Csv.Document(
        File.Contents(CsvFolderPath & "\vulnerabilities.csv"),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),

    // Apply the same types as the live API query so VRM_Report.pq sees an
    // identical schema regardless of data-source mode.
    // Dates arrive as ISO 8601 strings; Power Query parses them correctly.
    // Booleans arrive as "True"/"False" strings; type logical handles them.
    Typed = Table.TransformColumnTypes(Promoted, {
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
    }, MissingField.Ignore)
in
    Typed

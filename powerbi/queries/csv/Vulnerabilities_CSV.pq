// ============================================================================
// Vulnerabilities (CSV)  –  Defender portal Weaknesses export
// ============================================================================
// File: export-tvm-vulnerabilities.csv
// Export from: Security > Vulnerability Management > Weaknesses > Export
//
// Row 1 is a title line ("Vulnerabilities Export,...") – skipped.
// Row 2 contains the actual column headers.
//
// Headers: Name, Severity, CVSS v3, Epss score, Age (days), Published,
//          First detected, Updated, Has Exploit, Has Known Threats,
//          Has Associated Alerts, Related Software, Exposed Machines,
//          Description, Status
// ============================================================================

let
    Source = Csv.Document(
        File.Contents(CsvFolderPath & "\export-tvm-vulnerabilities.csv"),
        [Delimiter = ",", Columns = 15, Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),

    // Skip the title row, promote row 2 as headers
    SkipTitle = Table.Skip(Source, 1),
    Promoted  = Table.PromoteHeaders(SkipTitle, [PromoteAllScalars = true]),

    // Parse dates: portal uses "05 Mar, 2026" format – strip comma first
    CleanDates = Table.TransformColumns(Promoted, {
        {"Published",      each Text.Replace(_ ?? "", ",", ""), type text},
        {"First detected", each Text.Replace(_ ?? "", ",", ""), type text},
        {"Updated",        each Text.Replace(_ ?? "", ",", ""), type text}
    }),

    Typed = Table.TransformColumnTypes(CleanDates, {
        {"Name",                  type text},
        {"Severity",              type text},
        {"CVSS v3",               type number},
        {"Epss score",            type number},
        {"Age (days)",            Int64.Type},
        {"Published",             type date},
        {"First detected",        type date},
        {"Updated",               type date},
        {"Has Exploit",           type text},
        {"Has Known Threats",     type text},
        {"Has Associated Alerts", type text},
        {"Related Software",      type text},
        {"Exposed Machines",      Int64.Type},
        {"Description",           type text},
        {"Status",                type text}
    })
in
    Typed

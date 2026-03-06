// ============================================================================
// Machines (CSV)  –  Defender portal Devices export
// ============================================================================
// File: devices.csv
// Export from: Assets > Devices > Export
//
// Headers include: Device ID, Device Name, Device Type, OS Platform,
//                  Group, Device IPs, Risk Level, Exposure Level, etc.
// ============================================================================

let
    Source = Csv.Document(
        File.Contents(CsvFolderPath & "\devices.csv"),
        [Delimiter = ",", Encoding = 65001, QuoteStyle = QuoteStyle.Csv]
    ),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),

    // Rename to match the column names the API-mode Machines query uses,
    // so VRM_Report can reference them consistently
    Renamed = Table.RenameColumns(Promoted, {
        {"Device ID",    "id"},
        {"Device Name",  "computerDnsName"},
        {"OS Platform",  "osPlatform"},
        {"Group",        "rbacGroupName"},
        {"Device IPs",   "lastIpAddress"},
        {"Health Status", "healthStatus"},
        {"Risk Level",   "riskScore"},
        {"Exposure Level", "exposureLevel"},
        {"Device Type",  "portalDeviceType"}
    }, MissingField.Ignore),

    // Take only the first IP from the comma-separated list
    CleanIP = Table.TransformColumns(Renamed, {
        {"lastIpAddress", each Text.Trim(Text.BeforeDelimiter(_ ?? "", ",")), type text}
    }),

    Typed = Table.TransformColumnTypes(CleanIP, {
        {"id",               type text},
        {"computerDnsName",  type text},
        {"osPlatform",       type text},
        {"rbacGroupName",    type text},
        {"lastIpAddress",    type text},
        {"healthStatus",     type text},
        {"riskScore",        type text},
        {"exposureLevel",    type text},
        {"portalDeviceType", type text}
    }, MissingField.Ignore)
in
    Typed

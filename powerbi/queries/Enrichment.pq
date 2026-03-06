// ============================================================================
// Enrichment  –  Local JSON business-context data
// ============================================================================
// Loads asset-enrichment.json (same format as the Node.js project) and
// provides columns that Defender for Endpoint does not supply:
//   F – Device Type,  K – Asset Criticality,  L – Data Type,
//   M – Location,     N – Notes
//
// Change the FilePath parameter below to point to your enrichment file.
// ============================================================================

let
    FilePath = EnrichmentFilePath,

    RawJson  = Json.Document(File.Contents(FilePath)),

    // Extract defaults
    Defaults = RawJson[defaults],
    DefaultAssetCriticality = try Defaults[assetCriticality] otherwise "Moderate Impact",
    DefaultDataType         = try Defaults[dataType]         otherwise "End Point User",
    DefaultLocation         = try Defaults[location]         otherwise "Internal",
    DefaultDeviceType       = try Defaults[deviceType]       otherwise "Desktop",

    // Extract asset list → table
    Assets  = RawJson[assets],
    AsTable = Table.FromList(Assets, Splitter.SplitByNothing(), null, null, ExtraValues.Error),
    Expanded = Table.ExpandRecordColumn(
        AsTable, "Column1",
        {"matchKey", "matchType", "deviceType", "assetCriticality", "dataType", "location", "notes"}
    ),

    // Replace nulls with defaults
    WithDefaults = Table.ReplaceValue(
        Table.ReplaceValue(
            Table.ReplaceValue(
                Table.ReplaceValue(
                    Expanded,
                    null, DefaultDeviceType,
                    Replacer.ReplaceValue, {"deviceType"}
                ),
                null, DefaultAssetCriticality,
                Replacer.ReplaceValue, {"assetCriticality"}
            ),
            null, DefaultDataType,
            Replacer.ReplaceValue, {"dataType"}
        ),
        null, DefaultLocation,
        Replacer.ReplaceValue, {"location"}
    ),

    // Fill empty notes with blank string
    Final = Table.ReplaceValue(WithDefaults, null, "", Replacer.ReplaceValue, {"notes"}),

    // Record of default values so VRM_Report can reference them
    _Defaults = [
        DefaultDeviceType       = DefaultDeviceType,
        DefaultAssetCriticality = DefaultAssetCriticality,
        DefaultDataType         = DefaultDataType,
        DefaultLocation         = DefaultLocation
    ]
in
    Final

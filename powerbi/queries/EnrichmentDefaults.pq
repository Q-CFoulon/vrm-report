// ============================================================================
// EnrichmentDefaults  –  Expose defaults from enrichment JSON
// ============================================================================
// Reads the same JSON file as Enrichment and returns a single record
// containing the default values.  Referenced by VRM_Report when no
// enrichment match is found.
// ============================================================================

let
    FilePath = EnrichmentFilePath,
    RawJson  = Json.Document(File.Contents(FilePath)),
    Defaults = RawJson[defaults],

    Result = [
        DeviceType       = try Defaults[deviceType]       otherwise "Desktop",
        AssetCriticality = try Defaults[assetCriticality] otherwise "Moderate Impact",
        DataType         = try Defaults[dataType]         otherwise "End Point User",
        Location         = try Defaults[location]         otherwise "Internal"
    ]
in
    Result

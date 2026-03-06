// ============================================================================
// VRM_Report (CSV)  –  Final report table  (columns A – O)
// ============================================================================
// CSV-mode variant.  The Defender portal Weaknesses export is CVE-level
// (one row per vulnerability, not per machine×CVE), so this query produces
// one row per CVE.  The Machines_CSV table is loaded as a supplementary
// reference for device-fleet statistics but cannot be joined per-row since
// the portal export does not include a machine-to-CVE mapping.
//
// Depends on: Vulnerabilities (CSV override), Enrichment, EnrichmentDefaults
// ============================================================================

let
    // ── 0.  Load source queries ─────────────────────────────────────────
    Vulns    = Vulnerabilities,
    Defaults = EnrichmentDefaults,

    // ── 1.  Add row index for Unique ID ─────────────────────────────────
    Indexed = Table.AddIndexColumn(Vulns, "RowNum", 1, 1, Int64.Type),

    // ── 2.  Compute derived columns (A – O) ────────────────────────────

    // --- Column A: Unique ID ---
    AddUniqueId = Table.AddColumn(Indexed, "A_UniqueId",
        each Text.From([RowNum]), type text),

    // --- Column B: Criticality ---
    AddCriticality = Table.AddColumn(AddUniqueId, "B_Criticality", each
        if [#"Has Exploit"] = "True" then "Exploitable"
        else if [Severity] = "Critical" then "Critical"
        else if [Severity] = "High"     then "High"
        else if [Severity] = "Medium"   then "Medium"
        else "Low",
        type text),

    // --- Column C: CVE# / CVSS ---
    AddCveId = Table.AddColumn(AddCriticality, "C_CveId",
        each [Name], type text),
    AddCvss  = Table.AddColumn(AddCveId, "C_CvssScore",
        each [#"CVSS v3"], type number),

    // --- Column D: Description ---
    AddDesc = Table.AddColumn(AddCvss, "D_Description",
        each [Description], type text),

    // --- Column E: Device OS ---
    // Per-device OS is not available in CVE-level export; show exposed count
    AddOS = Table.AddColumn(AddDesc, "E_DeviceOS", each
        let n = try [#"Exposed Machines"] otherwise 0 in
        if n = 1 then "1 device"
        else Text.From(n) & " devices",
        type text),

    // --- Column F: Device Type  (from enrichment defaults) ---
    AddDeviceType = Table.AddColumn(AddOS, "F_DeviceType", each
        Defaults[DeviceType],
        type text),

    // --- Column G: Date First Detected ---
    AddFirstDetected = Table.AddColumn(AddDeviceType, "G_DateFirstDetected", each
        [#"First detected"],
        type date),

    // --- Column H: Date Last Detected ---
    AddLastDetected = Table.AddColumn(AddFirstDetected, "H_DateLastDetected", each
        [Updated],
        type date),

    // --- Column I: Status  (aging bucket from Age (days) column) ---
    AddStatus = Table.AddColumn(AddLastDetected, "I_Status", each
        let st = [Status] ?? "" in
        if st = "NoActionRequired" or st = "Resolved" then "Patched"
        else
            let days = try [#"Age (days)"] otherwise 0 in
            if days > 90 then "Pending > 3 months"
            else if days > 60 then "Pending > 2 months"
            else if days > 30 then "Pending > 1 month"
            else "Pending < 1 month",
        type text),

    // --- Column J: Risk Acceptance ---
    AddRisk = Table.AddColumn(AddStatus, "J_RiskAcceptance", each
        let st = [Status] ?? "" in
        if st = "Exception" or st = "UnderException" or st = "PartialException"
        then "Yes" else "No",
        type text),

    // --- Column K: Asset Criticality  (enrichment defaults) ---
    AddAssetCrit = Table.AddColumn(AddRisk, "K_AssetCriticality", each
        Defaults[AssetCriticality],
        type text),

    // --- Column L: Data Type ---
    AddDataType = Table.AddColumn(AddAssetCrit, "L_DataType", each
        Defaults[DataType],
        type text),

    // --- Column M: Location ---
    AddLocation = Table.AddColumn(AddDataType, "M_Location", each
        Defaults[Location],
        type text),

    // --- Column N: Notes ---
    AddNotes = Table.AddColumn(AddLocation, "N_Notes", each
        "", type text),

    // --- Column O: Product ---
    AddProduct = Table.AddColumn(AddNotes, "O_Product", each
        [#"Related Software"] ?? "",
        type text),

    // --- Column P: Machine Name (not available in CSV export; left blank) ---
    AddMachineName = Table.AddColumn(AddProduct, "P_MachineName", each "", type text),

    // ── 3.  Select only the final report columns ───────────────────────
    FinalColumns = Table.SelectColumns(AddMachineName, {
        "A_UniqueId", "B_Criticality", "C_CveId", "C_CvssScore",
        "D_Description", "E_DeviceOS", "F_DeviceType",
        "G_DateFirstDetected", "H_DateLastDetected",
        "I_Status", "J_RiskAcceptance",
        "K_AssetCriticality", "L_DataType", "M_Location",
        "N_Notes", "O_Product", "P_MachineName"
    }),

    Renamed = Table.RenameColumns(FinalColumns, {
        {"A_UniqueId",          "Unique ID"},
        {"B_Criticality",       "Criticality"},
        {"C_CveId",             "CVE#"},
        {"C_CvssScore",         "CVSS Score"},
        {"D_Description",       "Description"},
        {"E_DeviceOS",          "Device OS"},
        {"F_DeviceType",        "Device Type"},
        {"G_DateFirstDetected", "Date First Detected"},
        {"H_DateLastDetected",  "Date Last Detected"},
        {"I_Status",            "Status"},
        {"J_RiskAcceptance",    "Risk Acceptance"},
        {"K_AssetCriticality",  "Asset Criticality"},
        {"L_DataType",          "Data Type"},
        {"M_Location",          "Location"},
        {"N_Notes",             "Notes"},
        {"O_Product",           "Product"},
        {"P_MachineName",       "Machine Name"}
    })
in
    Renamed
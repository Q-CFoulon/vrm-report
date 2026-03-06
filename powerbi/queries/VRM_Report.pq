// ============================================================================
// VRM_Report  –  Final report table  (columns A – O)
// ============================================================================
// Joins MachineVulnerabilities × Vulnerabilities × Machines × Enrichment and
// computes every derived column exactly as the TypeScript mapper does.
//
// Depends on queries:
//   MachineVulnerabilities, Vulnerabilities, Machines,
//   Enrichment, EnrichmentDefaults, fn_PaginatedGet
// ============================================================================

let
    // ── 0.  Load source queries ─────────────────────────────────────────
    MV       = MachineVulnerabilities,
    Vulns    = Vulnerabilities,
    Machines = Machines,
    Enrich   = Enrichment,
    Defaults = EnrichmentDefaults,

    // ── 1.  Join MachineVulnerabilities → Vulnerabilities on cveId ──────
    JoinVuln = Table.NestedJoin(
        MV, {"cveId"}, Vulns, {"id"}, "vuln", JoinKind.Inner
    ),
    ExpandVuln = Table.ExpandTableColumn(JoinVuln, "vuln", {
        "description", "severity", "cvssV3", "publishedOn", "updatedOn",
        "firstDetected", "publicExploit", "exploitVerified", "status"
    }, {
        "v.description", "v.severity", "v.cvssV3", "v.publishedOn",
        "v.updatedOn", "v.firstDetected", "v.publicExploit",
        "v.exploitVerified", "v.status"
    }),

    // ── 2.  Join → Machines on machineId for OS / hostname ─────────────
    JoinMachine = Table.NestedJoin(
        ExpandVuln, {"machineId"}, Machines, {"id"}, "machine", JoinKind.LeftOuter
    ),
    ExpandMachine = Table.ExpandTableColumn(JoinMachine, "machine", {
        "computerDnsName", "osPlatform", "rbacGroupName", "lastIpAddress"
    }, {
        "m.computerDnsName", "m.osPlatform", "m.rbacGroupName", "m.lastIpAddress"
    }),

    // ── 3.  Join → Enrichment  (try hostname, then rbacGroup) ──────────
    //        Hostname match
    JoinEnrichHost = Table.NestedJoin(
        ExpandMachine, {"m.computerDnsName"},
        Table.SelectRows(Enrich, each [matchType] = "hostname"), {"matchKey"},
        "enrich_host", JoinKind.LeftOuter
    ),
    ExpandEnrichHost = Table.ExpandTableColumn(JoinEnrichHost, "enrich_host", {
        "deviceType", "assetCriticality", "dataType", "location", "notes"
    }, {
        "eh.deviceType", "eh.assetCriticality", "eh.dataType", "eh.location", "eh.notes"
    }),

    //        RBAC group match (fallback)
    JoinEnrichGroup = Table.NestedJoin(
        ExpandEnrichHost, {"m.rbacGroupName"},
        Table.SelectRows(Enrich, each [matchType] = "rbacGroup"), {"matchKey"},
        "enrich_grp", JoinKind.LeftOuter
    ),
    ExpandEnrichGroup = Table.ExpandTableColumn(JoinEnrichGroup, "enrich_grp", {
        "deviceType", "assetCriticality", "dataType", "location", "notes"
    }, {
        "eg.deviceType", "eg.assetCriticality", "eg.dataType", "eg.location", "eg.notes"
    }),

    //        IP match (second fallback)
    JoinEnrichIP = Table.NestedJoin(
        ExpandEnrichGroup, {"m.lastIpAddress"},
        Table.SelectRows(Enrich, each [matchType] = "ipAddress"), {"matchKey"},
        "enrich_ip", JoinKind.LeftOuter
    ),
    ExpandEnrichIP = Table.ExpandTableColumn(JoinEnrichIP, "enrich_ip", {
        "deviceType", "assetCriticality", "dataType", "location", "notes"
    }, {
        "ei.deviceType", "ei.assetCriticality", "ei.dataType", "ei.location", "ei.notes"
    }),

    // ── 4.  Add row index for Unique ID (column A) ─────────────────────
    Indexed = Table.AddIndexColumn(ExpandEnrichIP, "RowNum", 1, 1, Int64.Type),

    // ── 5.  Compute derived columns ────────────────────────────────────

    // --- Column A: Unique ID ---
    AddUniqueId = Table.AddColumn(Indexed, "A_UniqueId",
        each Text.From([RowNum]), type text),

    // --- Column B: Criticality ---
    //     If publicExploit or exploitVerified → "Exploitable"
    //     else map severity string
    AddCriticality = Table.AddColumn(AddUniqueId, "B_Criticality", each
        if [v.publicExploit] = true or [v.exploitVerified] = true then "Exploitable"
        else if [v.severity] = "Critical" then "Critical"
        else if [v.severity] = "High"     then "High"
        else if [v.severity] = "Medium"   then "Medium"
        else "Low",
        type text),

    // --- Column C: CVE / CVSS ---
    AddCveId = Table.AddColumn(AddCriticality, "C_CveId",
        each [cveId], type text),
    AddCvss  = Table.AddColumn(AddCveId, "C_CvssScore",
        each [v.cvssV3], type number),

    // --- Column D: Description ---
    AddDesc = Table.AddColumn(AddCvss, "D_Description",
        each [v.description], type text),

    // --- Column E: Device OS  (normalise the API's osPlatform string) ---
    AddOS = Table.AddColumn(AddDesc, "E_DeviceOS", each
        let p = Text.Lower([m.osPlatform] ?? "") in
        if Text.Contains(p, "windows11")         then "Windows 11"
        else if Text.Contains(p, "windows10")    then "Windows 10"
        else if Text.Contains(p, "windowsserver2022") then "Windows Server 2022"
        else if Text.Contains(p, "windowsserver2019") or Text.Contains(p, "windows_server_2019") then "Windows Server 2019"
        else if Text.Contains(p, "windowsserver2016") or Text.Contains(p, "windows_server_2016") then "Windows Server 2016"
        else if Text.Contains(p, "windows_server_2012") then "Windows Server 2012 R2"
        else if Text.Contains(p, "linux")   then "Linux"
        else if Text.Contains(p, "macos")   then "macOS"
        else if Text.Contains(p, "ios")     then "iOS"
        else if Text.Contains(p, "android") then "Android"
        else ([m.osPlatform] ?? "Unknown"),
        type text),

    // --- Column F: Device Type  (enrichment → default) ---
    AddDeviceType = Table.AddColumn(AddOS, "F_DeviceType", each
        [eh.deviceType] ?? [eg.deviceType] ?? [ei.deviceType]
            ?? Defaults[DeviceType],
        type text),

    // --- Column G: Date First Detected ---
    AddFirstDetected = Table.AddColumn(AddDeviceType, "G_DateFirstDetected", each
        [v.firstDetected] ?? [v.publishedOn],
        type datetime),

    // --- Column H: Date Last Detected ---
    AddLastDetected = Table.AddColumn(AddFirstDetected, "H_DateLastDetected", each
        [v.updatedOn],
        type datetime),

    // --- Column I: Status  (aging bucket from first-detected) ---
    AddStatus = Table.AddColumn(AddLastDetected, "I_Status", each
        if [v.status] = "NoActionRequired" then "Patched"
        else
            let
                first = [v.firstDetected] ?? [v.publishedOn],
                days  = if first <> null
                        then Duration.TotalDays(DateTime.LocalNow() - first)
                        else 0
            in
                if days > 90 then "Pending > 3 months"
                else if days > 60 then "Pending > 2 months"
                else if days > 30 then "Pending > 1 month"
                else "Pending < 1 month",
        type text),

    // --- Column J: Risk Acceptance ---
    AddRisk = Table.AddColumn(AddStatus, "J_RiskAcceptance", each
        if [v.status] = "UnderException" or [v.status] = "PartialException"
        then "Yes" else "No",
        type text),

    // --- Column K: Asset Criticality ---
    AddAssetCrit = Table.AddColumn(AddRisk, "K_AssetCriticality", each
        [eh.assetCriticality] ?? [eg.assetCriticality] ?? [ei.assetCriticality]
            ?? Defaults[AssetCriticality],
        type text),

    // --- Column L: Data Type ---
    AddDataType = Table.AddColumn(AddAssetCrit, "L_DataType", each
        [eh.dataType] ?? [eg.dataType] ?? [ei.dataType]
            ?? Defaults[DataType],
        type text),

    // --- Column M: Location ---
    AddLocation = Table.AddColumn(AddDataType, "M_Location", each
        [eh.location] ?? [eg.location] ?? [ei.location]
            ?? Defaults[Location],
        type text),

    // --- Column N: Notes ---
    AddNotes = Table.AddColumn(AddLocation, "N_Notes", each
        [eh.notes] ?? [eg.notes] ?? [ei.notes] ?? "",
        type text),

    // --- Column O: Product (bonus context from Defender) ---
    AddProduct = Table.AddColumn(AddNotes, "O_Product", each
        [productName] ?? "",
        type text),

    // ── 6.  Select only the final report columns ───────────────────────
    FinalColumns = Table.SelectColumns(AddProduct, {
        "A_UniqueId", "B_Criticality", "C_CveId", "C_CvssScore",
        "D_Description", "E_DeviceOS", "F_DeviceType",
        "G_DateFirstDetected", "H_DateLastDetected",
        "I_Status", "J_RiskAcceptance",
        "K_AssetCriticality", "L_DataType", "M_Location",
        "N_Notes", "O_Product"
    }),

    // Friendly column names for the report
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
        {"O_Product",           "Product"}
    })
in
    Renamed

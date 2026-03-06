// ============================================================================
// fn_PaginatedGet  –  Reusable OData pagination helper
// ============================================================================
// Calls the Defender for Endpoint REST API and follows @odata.nextLink until
// all pages are consumed.  Returns a combined list of records.
//
// Parameters:
//   relativePath  – e.g. "/api/vulnerabilities"
//
// Prerequisites:
//   • Data source privacy for api.securitycenter.microsoft.com set to
//     Organizational.
//   • Credentials configured as "Organizational account" for the base URL.
// ============================================================================

let
    fn = (relativePath as text) as list =>
        let
            BaseUrl = DefenderApiBaseUrl,

            // First page uses RelativePath option for credential resolution
            GetFirstPage = () =>
                let
                    Raw  = Web.Contents(BaseUrl, [RelativePath = relativePath, Headers = [Accept = "application/json"]]),
                    Json = Json.Document(Raw),
                    Data = Json[value],
                    Next = try Json[#"@odata.nextLink"] otherwise null
                in
                    [Data = Data, NextLink = Next],

            // Subsequent pages follow the full @odata.nextLink URL
            GetNextPage = (url as text) =>
                let
                    Raw  = Web.Contents(url),
                    Json = Json.Document(Raw),
                    Data = Json[value],
                    Next = try Json[#"@odata.nextLink"] otherwise null
                in
                    [Data = Data, NextLink = Next],

            Accumulate = (accum as list, nextUrl as nullable text, isFirst as logical) =>
                let
                    Page   = if isFirst then GetFirstPage() else GetNextPage(nextUrl),
                    Merged = accum & Page[Data],
                    Result = if Page[NextLink] <> null
                             then @Accumulate(Merged, Page[NextLink], false)
                             else Merged
                in
                    Result,

            AllRecords = Accumulate({}, null, true)
        in
            AllRecords
in
    fn
